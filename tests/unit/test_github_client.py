"""The GitHub client, against a mocked HTTP layer with a fake clock and sleeper."""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from newsoc_code.github.client import GitHubClient, GitHubError

API = "https://api.example.test"
INSTALLATION = 4242
REPO = "acme/widgets"


@pytest.fixture(scope="module")
def keys():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem, public


class Clock:
    def __init__(self, now: float = 1_800_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def sleeps():
    return []


@pytest.fixture
def client(keys, clock, sleeps):
    return GitHubClient(
        app_id=777,
        private_key=keys[0],
        api_url=API,
        clock=clock,
        sleep=sleeps.append,
        max_retries=3,
    )


def expiry(clock: Clock, seconds: float = 3600) -> str:
    return datetime.fromtimestamp(clock.now + seconds, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def token_route(mock, clock, token="ghs_token1", **kw):
    return mock.post(f"{API}/app/installations/{INSTALLATION}/access_tokens").mock(
        return_value=httpx.Response(201, json={"token": token, "expires_at": expiry(clock, **kw)})
    )


# ---- authentication ---------------------------------------------------------------------------


def test_app_jwt_is_signed_with_the_app_key_and_short_lived(client, keys, clock):
    claims = jwt.decode(
        client.app_jwt(),
        keys[1],
        algorithms=["RS256"],
        options={"verify_exp": False, "verify_iat": False},
    )
    assert claims["iss"] == "777"
    assert claims["iat"] == int(clock.now) - 60  # backdated to tolerate clock drift
    assert claims["exp"] - claims["iat"] <= 600  # GitHub's limit is ten minutes


@respx.mock
def test_installation_token_is_requested_with_the_app_jwt_and_cached(client, clock, keys):
    route = token_route(respx, clock)

    assert client.installation_token(INSTALLATION) == "ghs_token1"
    assert client.installation_token(INSTALLATION) == "ghs_token1"

    assert route.call_count == 1
    auth = route.calls[0].request.headers["authorization"]
    assert auth.startswith("Bearer ")
    assert (
        jwt.decode(
            auth[7:],
            keys[1],
            algorithms=["RS256"],
            options={"verify_exp": False, "verify_iat": False},
        )["iss"]
        == "777"
    )


@respx.mock
def test_token_is_refreshed_before_it_expires(client, clock):
    route = token_route(respx, clock, seconds=3600)
    client.installation_token(INSTALLATION)
    clock.now += 3600 - 200  # inside the five-minute margin
    client.installation_token(INSTALLATION)
    assert route.call_count == 2


@respx.mock
def test_narrowed_tokens_are_cached_separately(client, clock):
    route = token_route(respx, clock)
    client.installation_token(INSTALLATION)
    client.installation_token(
        INSTALLATION, permissions={"contents": "read"}, repositories=["widgets"]
    )
    assert route.call_count == 2
    body = route.calls[1].request.read()
    assert b'"contents"' in body and b'"widgets"' in body


@respx.mock
def test_a_revoked_installation_token_is_replaced_once_on_401(client, clock):
    token_route(respx, clock)
    api = respx.get(f"{API}/repos/{REPO}/pulls/1/comments").mock(
        side_effect=[
            httpx.Response(401, json={"message": "Bad credentials"}),
            httpx.Response(200, json=[]),
        ]
    )
    resp = client._read(INSTALLATION, f"/repos/{REPO}/pulls/1/comments")
    assert resp.status_code == 200 and api.call_count == 2


# ---- retries and rate limits ------------------------------------------------------------------


@respx.mock
def test_server_errors_back_off_exponentially_then_succeed(client, clock, sleeps):
    token_route(respx, clock)
    respx.get(f"{API}/repos/{REPO}/x").mock(
        side_effect=[httpx.Response(502), httpx.Response(503), httpx.Response(200, json={"ok": 1})]
    )
    assert client._read(INSTALLATION, f"/repos/{REPO}/x").json() == {"ok": 1}
    assert sleeps == [1.0, 2.0]


@respx.mock
def test_persistent_server_errors_raise_after_the_retry_budget(client, clock, sleeps):
    token_route(respx, clock)
    respx.get(f"{API}/repos/{REPO}/x").mock(
        return_value=httpx.Response(500, json={"message": "boom"})
    )
    with pytest.raises(GitHubError) as err:
        client._read(INSTALLATION, f"/repos/{REPO}/x")
    assert err.value.status == 500
    assert len(sleeps) == 3  # max_retries


@respx.mock
def test_retry_after_header_is_honoured(client, clock, sleeps):
    token_route(respx, clock)
    respx.get(f"{API}/repos/{REPO}/x").mock(
        side_effect=[
            httpx.Response(429, headers={"retry-after": "7"}),
            httpx.Response(200, json={}),
        ]
    )
    client._read(INSTALLATION, f"/repos/{REPO}/x")
    assert sleeps == [7.0]


@respx.mock
def test_primary_rate_limit_waits_until_the_reset_time(client, clock, sleeps):
    token_route(respx, clock)
    reset = str(int(clock.now) + 20)
    respx.get(f"{API}/repos/{REPO}/x").mock(
        side_effect=[
            httpx.Response(
                403,
                headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": reset},
                json={"message": "API rate limit exceeded"},
            ),
            httpx.Response(200, json={}),
        ]
    )
    client._read(INSTALLATION, f"/repos/{REPO}/x")
    assert sleeps == [20.0]


@respx.mock
def test_a_very_long_rate_limit_wait_is_capped(client, clock, sleeps):
    token_route(respx, clock)
    reset = str(int(clock.now) + 3000)
    respx.get(f"{API}/repos/{REPO}/x").mock(
        side_effect=[
            httpx.Response(403, headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": reset}),
            httpx.Response(200, json={}),
        ]
    )
    client._read(INSTALLATION, f"/repos/{REPO}/x")
    assert sleeps == [60.0]


@respx.mock
def test_secondary_rate_limit_backs_off(client, clock, sleeps):
    token_route(respx, clock)
    respx.get(f"{API}/repos/{REPO}/x").mock(
        side_effect=[
            httpx.Response(403, json={"message": "You have exceeded a secondary rate limit."}),
            httpx.Response(200, json={}),
        ]
    )
    client._read(INSTALLATION, f"/repos/{REPO}/x")
    assert sleeps == [5.0]


@respx.mock
def test_a_permission_error_is_not_retried(client, clock, sleeps):
    token_route(respx, clock)
    route = respx.get(f"{API}/repos/{REPO}/x").mock(
        return_value=httpx.Response(403, json={"message": "Resource not accessible by integration"})
    )
    with pytest.raises(GitHubError) as err:
        client._read(INSTALLATION, f"/repos/{REPO}/x")
    assert err.value.status == 403 and route.call_count == 1 and sleeps == []


@respx.mock
def test_network_errors_are_retried(client, clock, sleeps):
    token_route(respx, clock)
    respx.get(f"{API}/repos/{REPO}/x").mock(
        side_effect=[httpx.ConnectError("down"), httpx.Response(200, json={})]
    )
    client._read(INSTALLATION, f"/repos/{REPO}/x")
    assert sleeps == [1.0]


# ---- the calls the worker uses ----------------------------------------------------------------


@respx.mock
def test_get_file_returns_text_or_none(client, clock):
    token_route(respx, clock)
    route = respx.get(f"{API}/repos/{REPO}/contents/.secpolicy.yml").mock(
        side_effect=[
            httpx.Response(200, text="mode: enforce\n"),
            httpx.Response(404, json={"message": "Not Found"}),
        ]
    )
    assert client.get_file(INSTALLATION, REPO, ".secpolicy.yml", "base123") == "mode: enforce\n"
    assert client.get_file(INSTALLATION, REPO, ".secpolicy.yml", "base123") is None
    request = route.calls[0].request
    assert request.url.params["ref"] == "base123"
    assert request.headers["accept"] == "application/vnd.github.raw+json"


@respx.mock
def test_pull_request_details_and_fork_detection(client, clock):
    token_route(respx, clock)

    def pr(head_repo):
        return {
            "head": {"sha": "h1", "repo": head_repo},
            "base": {"sha": "b1", "ref": "main", "repo": {"full_name": REPO}},
            "draft": False,
            "state": "open",
        }

    respx.get(f"{API}/repos/{REPO}/pulls/1").mock(
        return_value=httpx.Response(200, json=pr({"full_name": REPO}))
    )
    respx.get(f"{API}/repos/{REPO}/pulls/2").mock(
        return_value=httpx.Response(200, json=pr({"full_name": "evil/widgets"}))
    )
    respx.get(f"{API}/repos/{REPO}/pulls/3").mock(return_value=httpx.Response(200, json=pr(None)))

    assert not client.get_pull_request(INSTALLATION, REPO, 1).is_fork
    assert client.get_pull_request(INSTALLATION, REPO, 2).is_fork
    deleted = client.get_pull_request(INSTALLATION, REPO, 3)
    assert deleted.is_fork and deleted.head_repo is None  # a deleted fork is still a fork


@respx.mock
def test_compare_follows_pages_and_tracks_renames(client, clock):
    token_route(respx, clock)
    page1 = {
        "merge_base_commit": {"sha": "mb"},
        "ahead_by": 3,
        "behind_by": 1,
        "files": [{"filename": f"f{i}.py"} for i in range(100)],
    }
    page2 = {
        "merge_base_commit": {"sha": "mb"},
        "ahead_by": 3,
        "behind_by": 1,
        "files": [{"filename": "new.py", "previous_filename": "old.py"}]
        + [{"filename": f"g{i}.py"} for i in range(29)],
    }
    respx.get(f"{API}/repos/{REPO}/compare/base...head", params={"page": 1}).mock(
        return_value=httpx.Response(200, json=page1)
    )
    respx.get(f"{API}/repos/{REPO}/compare/base...head", params={"page": 2}).mock(
        return_value=httpx.Response(200, json=page2)
    )

    cmp = client.compare(INSTALLATION, REPO, "base", "head")

    assert cmp.merge_base == "mb" and cmp.ahead_by == 3 and cmp.behind_by == 1
    assert len(cmp.files) == 130
    assert cmp.renamed == (("old.py", "new.py"),)


@respx.mock
def test_create_and_complete_a_check_run(client, clock):
    token_route(respx, clock)
    create = respx.post(f"{API}/repos/{REPO}/check-runs").mock(
        return_value=httpx.Response(201, json={"id": 99})
    )
    patch = respx.patch(f"{API}/repos/{REPO}/check-runs/99").mock(
        return_value=httpx.Response(200, json={})
    )

    run_id = client.create_check_run(
        INSTALLATION,
        REPO,
        name="newsoc/security",
        head_sha="h1",
        external_id="job-1",
        title="Scanning",
        summary="queued",
    )
    client.update_check_run(
        INSTALLATION,
        REPO,
        run_id,
        title="1 blocking finding(s)",
        summary="s",
        conclusion="failure",
        annotations=[
            {
                "path": "a.js",
                "start_line": 1,
                "end_line": 1,
                "annotation_level": "failure",
                "message": "m",
            }
        ],
    )

    body = create.calls[0].request
    assert run_id == 99
    assert (
        b'"in_progress"' in body.read() and b'"newsoc/security"' in create.calls[0].request.content
    )
    sent = patch.calls[0].request.content
    assert b'"completed"' in sent and b'"failure"' in sent and b'"annotations"' in sent


@respx.mock
def test_more_than_fifty_annotations_in_one_call_is_refused(client, clock):
    token_route(respx, clock)
    too_many = [
        {"path": "a", "start_line": 1, "end_line": 1, "annotation_level": "notice", "message": "m"}
    ] * 51
    with pytest.raises(ValueError, match="at most 50"):
        client.update_check_run(INSTALLATION, REPO, 1, title="t", summary="s", annotations=too_many)


@respx.mock
def test_list_comments_pages_through_everything(client, clock):
    token_route(respx, clock)
    respx.get(f"{API}/repos/{REPO}/issues/5/comments", params={"page": 1}).mock(
        return_value=httpx.Response(200, json=[{"id": i} for i in range(100)])
    )
    respx.get(f"{API}/repos/{REPO}/issues/5/comments", params={"page": 2}).mock(
        return_value=httpx.Response(200, json=[{"id": 100}])
    )
    assert len(client.list_comments(INSTALLATION, REPO, 5)) == 101


# ---- write serialisation ---------------------------------------------------------------------


def test_writes_for_one_installation_never_overlap(keys, clock):
    active, peak = 0, 0
    lock = threading.Lock()

    def slow_handler(request: httpx.Request) -> httpx.Response:
        nonlocal active, peak
        if request.url.path.endswith("access_tokens"):
            return httpx.Response(201, json={"token": "t", "expires_at": expiry(clock)})
        with lock:
            active += 1
            peak = max(peak, active)
        time.sleep(0.05)
        with lock:
            active -= 1
        return httpx.Response(200, json={})

    client = GitHubClient(
        777,
        keys[0],
        api_url=API,
        http=httpx.Client(transport=httpx.MockTransport(slow_handler)),
        clock=clock,
        sleep=lambda s: None,
    )
    client.installation_token(INSTALLATION)  # warm the token so only the writes are timed
    threads = [
        threading.Thread(target=client.update_comment, args=(INSTALLATION, REPO, i, "x"))
        for i in range(6)
    ]
    [t.start() for t in threads]
    [t.join() for t in threads]

    assert peak == 1, "mutations for one installation must be serialised"


def test_the_default_http_timeout_is_set():
    assert GitHubClient(1, "k")._http.timeout.read == 30.0
