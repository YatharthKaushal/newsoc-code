"""The webhook receiver over HTTP, backed by a real database."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import github_payloads as gh
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from newsoc_code.app.main import create_app
from newsoc_code.config import Settings
from newsoc_code.db.models import Installation, Repository, ScanJob, WebhookDelivery
from newsoc_code.github.signature import sign

pytestmark = pytest.mark.pg
SECRET = b"test-webhook-secret"

Send = Callable[..., Any]


@pytest.fixture
def client(db: sessionmaker[Session]) -> TestClient:
    app = create_app(Settings(), session_factory=db, webhook_secret=SECRET, app_id=gh.APP_ID)
    return TestClient(app)


@pytest.fixture
def send(client: TestClient) -> Send:
    counter = iter(range(1, 10_000))

    def _send(
        event: str,
        payload: dict[str, Any] | bytes,
        *,
        delivery: str | None = None,
        signature: str | None = "auto",
        secret: bytes = SECRET,
    ) -> Any:
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        headers = {
            "x-github-event": event,
            "x-github-delivery": delivery or f"delivery-{next(counter)}",
            "content-type": "application/json",
        }
        if signature == "auto":
            headers["x-hub-signature-256"] = sign(secret, body)
        elif signature is not None:
            headers["x-hub-signature-256"] = signature
        return client.post("/webhooks/github", content=body, headers=headers)

    return _send


def jobs_in(db: sessionmaker[Session]) -> list[ScanJob]:
    with db() as s:
        return list(s.scalars(select(ScanJob).order_by(ScanJob.id)))


def count(db: sessionmaker[Session], model: type) -> int:
    with db() as s:
        return int(s.scalar(select(func.count()).select_from(model)) or 0)


# ---- authentication --------------------------------------------------------------------------


@pytest.mark.parametrize("signature", [None, "sha256=" + "0" * 64, "sha1=abc", "garbage"])
def test_bad_signature_is_rejected_and_nothing_is_stored(
    send: Send, db: sessionmaker[Session], signature: str | None
) -> None:
    resp = send("pull_request", gh.pull_request(), signature=signature)
    assert resp.status_code == 401
    assert resp.json() == {"error": "invalid signature"}
    assert count(db, WebhookDelivery) == 0 and count(db, ScanJob) == 0


def test_signature_from_another_secret_is_rejected(send: Send, db: sessionmaker[Session]) -> None:
    assert send("pull_request", gh.pull_request(), secret=b"attacker").status_code == 401
    assert count(db, ScanJob) == 0


def test_signature_is_checked_before_the_body_is_parsed(send: Send) -> None:
    """Unsigned garbage gets a 401, not a 400 that reveals how the body is parsed."""
    assert send("pull_request", b"{not json", signature=None).status_code == 401


def test_signed_garbage_is_a_400(send: Send, db: sessionmaker[Session]) -> None:
    assert send("pull_request", b"{not json").status_code == 400
    assert send("pull_request", b"[1, 2]").status_code == 400
    assert count(db, WebhookDelivery) == 0


def test_missing_event_or_delivery_headers_are_a_400(client: TestClient) -> None:
    body = json.dumps(gh.pull_request()).encode()
    resp = client.post(
        "/webhooks/github", content=body, headers={"x-hub-signature-256": sign(SECRET, body)}
    )
    assert resp.status_code == 400


def test_oversized_payloads_are_refused(send: Send, db: sessionmaker[Session]) -> None:
    resp = send("push", b"x" * 2_500_000)
    assert resp.status_code == 413
    assert count(db, WebhookDelivery) == 0


# ---- pull requests ---------------------------------------------------------------------------


def test_opened_pull_request_queues_a_scan_and_returns_202(
    send: Send, db: sessionmaker[Session]
) -> None:
    resp = send("pull_request", gh.pull_request("opened"))
    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "queued" and len(body["jobs"]) == 1

    [job] = jobs_in(db)
    assert (job.pr_number, job.head_sha, job.base_sha, job.trigger) == (
        7,
        gh.HEAD_SHA,
        gh.BASE_SHA,
        "pull_request",
    )
    with db() as s:
        assert s.get(Installation, gh.INSTALLATION_ID) is not None  # created lazily
        repo = s.get(Repository, gh.REPO_ID)
        assert repo is not None and repo.full_name == "acme/app"


def test_a_redelivered_webhook_is_processed_once(send: Send, db: sessionmaker[Session]) -> None:
    first = send("pull_request", gh.pull_request(), delivery="d-1")
    again = send("pull_request", gh.pull_request(), delivery="d-1")
    assert first.status_code == 202
    assert again.status_code == 200 and again.json() == {"status": "duplicate"}
    assert count(db, ScanJob) == 1 and count(db, WebhookDelivery) == 1


def test_the_same_commit_delivered_twice_under_different_ids_queues_once(
    send: Send, db: sessionmaker[Session]
) -> None:
    send("pull_request", gh.pull_request(), delivery="d-1")
    resp = send("pull_request", gh.pull_request(), delivery="d-2")
    assert resp.status_code == 200 and resp.json()["status"] == "ignored"
    assert count(db, ScanJob) == 1 and count(db, WebhookDelivery) == 2


def test_a_second_push_supersedes_the_first_scan(send: Send, db: sessionmaker[Session]) -> None:
    send("pull_request", gh.pull_request("opened", head_sha="1" * 40))
    resp = send("pull_request", gh.pull_request("synchronize", head_sha="2" * 40))
    old, new = jobs_in(db)
    assert (old.status, new.status) == ("superseded", "queued")
    assert resp.json()["jobs"] == [new.id]


def test_closing_a_pull_request_stops_its_work(send: Send, db: sessionmaker[Session]) -> None:
    send("pull_request", gh.pull_request("opened"))
    resp = send("pull_request", gh.pull_request("closed"))
    [job] = jobs_in(db)
    assert job.status == "superseded"
    assert resp.status_code == 200 and resp.json()["superseded"] == [job.id]


def test_draft_pull_requests_are_not_queued_until_ready(
    send: Send, db: sessionmaker[Session]
) -> None:
    assert send("pull_request", gh.pull_request("opened", draft=True)).status_code == 200
    assert count(db, ScanJob) == 0
    assert send("pull_request", gh.pull_request("ready_for_review")).status_code == 202
    assert count(db, ScanJob) == 1


def test_fork_pull_requests_are_flagged_on_the_job(send: Send, db: sessionmaker[Session]) -> None:
    send("pull_request", gh.pull_request(from_fork=True))
    [job] = jobs_in(db)
    assert job.is_fork


# ---- other events ----------------------------------------------------------------------------


def test_push_to_the_default_branch_queues_a_baseline_scan(
    send: Send, db: sessionmaker[Session]
) -> None:
    assert send("push", gh.push()).status_code == 202
    [job] = jobs_in(db)
    assert (job.trigger, job.pr_number) == ("push", None)


def test_push_to_a_feature_branch_is_ignored(send: Send, db: sessionmaker[Session]) -> None:
    assert send("push", gh.push("refs/heads/feature")).status_code == 200
    assert count(db, ScanJob) == 0


def test_merge_group_queues_a_scan_of_the_group_head(send: Send, db: sessionmaker[Session]) -> None:
    send("merge_group", gh.merge_group())
    [job] = jobs_in(db)
    assert (job.trigger, job.head_sha) == ("merge_group", "c" * 40)


def test_rerequested_check_run_queues_a_new_scan(send: Send, db: sessionmaker[Session]) -> None:
    send("pull_request", gh.pull_request())
    with db() as s:  # the first scan has finished
        job = s.scalars(select(ScanJob)).one()
        job.status = "done"
        s.commit()
    assert send("check_run", gh.check_run_rerequested()).status_code == 202
    assert [j.status for j in jobs_in(db)] == ["done", "queued"]


def test_ping_is_acknowledged(send: Send) -> None:
    resp = send("ping", {"zen": "Design for failure.", "hook_id": 1})
    assert resp.status_code == 200 and resp.json()["status"] == "ignored"


def test_unknown_events_are_acknowledged_not_errors(send: Send) -> None:
    assert send("star", {"action": "created"}).status_code == 200


# ---- installations ---------------------------------------------------------------------------


def test_installation_created_records_the_repositories(
    send: Send, db: sessionmaker[Session]
) -> None:
    send("installation", gh.installation("created"))
    with db() as s:
        names = sorted(s.scalars(select(Repository.full_name)))
    assert names == ["acme/app", "acme/other"]


def test_suspended_installations_are_not_scanned(send: Send, db: sessionmaker[Session]) -> None:
    send("installation", gh.installation("created"))
    send("installation", gh.installation("suspend"))
    resp = send("pull_request", gh.pull_request())
    assert resp.status_code == 200 and "suspended" in resp.json()["note"]
    assert count(db, ScanJob) == 0

    send("installation", gh.installation("unsuspend"))
    assert send("pull_request", gh.pull_request(number=8, head_sha="3" * 40)).status_code == 202


def test_disabled_repositories_are_not_scanned(send: Send, db: sessionmaker[Session]) -> None:
    send("installation", gh.installation("created"))
    with db() as s:
        repo = s.get(Repository, gh.REPO_ID)
        assert repo is not None
        repo.enabled = False
        s.commit()
    resp = send("pull_request", gh.pull_request())
    assert resp.status_code == 200 and "disabled" in resp.json()["note"]


def test_deleting_the_installation_removes_its_data(send: Send, db: sessionmaker[Session]) -> None:
    send("pull_request", gh.pull_request())
    send("installation", gh.installation("deleted"))
    assert (count(db, Installation), count(db, Repository), count(db, ScanJob)) == (0, 0, 0)


def test_repositories_added_and_removed(send: Send, db: sessionmaker[Session]) -> None:
    send("installation", gh.installation("created", repos=[(1, "acme/a")]))
    send("installation_repositories", gh.installation_repositories(added=[(2, "acme/b")]))
    send("installation_repositories", gh.installation_repositories(removed=[(1, "acme/a")]))
    with db() as s:
        assert list(s.scalars(select(Repository.full_name))) == ["acme/b"]


def test_a_renamed_repository_keeps_its_id(send: Send, db: sessionmaker[Session]) -> None:
    send("pull_request", gh.pull_request(repo_name="acme/app", head_sha="1" * 40))
    send("pull_request", gh.pull_request(repo_name="acme/app-renamed", number=8, head_sha="2" * 40))
    with db() as s:
        assert list(s.scalars(select(Repository.full_name))) == ["acme/app-renamed"]


# ---- failure handling and health -------------------------------------------------------------


def test_a_processing_failure_is_not_recorded_so_redelivery_works(
    send: Send, db: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    from newsoc_code.app import webhooks

    def boom(*a: Any, **k: Any) -> None:
        raise RuntimeError("database exploded")

    monkeypatch.setattr(webhooks, "apply_actions", boom)
    with pytest.raises(RuntimeError):
        send("pull_request", gh.pull_request(), delivery="d-1")
    assert count(db, WebhookDelivery) == 0  # rolled back, not marked as seen

    monkeypatch.undo()
    assert send("pull_request", gh.pull_request(), delivery="d-1").status_code == 202
    assert count(db, ScanJob) == 1


def test_healthz(client: TestClient) -> None:
    resp = client.get("/healthz")
    assert resp.status_code == 200 and resp.json() == {"status": "ok"}


def test_no_documentation_endpoints_are_exposed(client: TestClient) -> None:
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


def test_missing_webhook_secret_fails_at_startup(tmp_path: Any) -> None:
    settings = Settings(github_webhook_secret_path=tmp_path / "missing")
    with pytest.raises(FileNotFoundError, match="webhook_secret"):
        create_app(settings, session_factory=None)
