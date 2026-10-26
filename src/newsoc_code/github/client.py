"""A small GitHub REST client for exactly what the Code arm needs.

Authentication is GitHub App auth: a short-lived JWT signed with the app's private key mints
installation access tokens, which are cached until shortly before they expire. Everything is
injectable (HTTP client, clock, sleeper) so retry and rate-limit behaviour is unit-testable.

Write calls are serialised per installation, which avoids GitHub's secondary rate limits for
bursts of mutations.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx
import jwt

API_VERSION = "2022-11-28"
TOKEN_REFRESH_MARGIN_S = 300
JWT_LIFETIME_S = 540  # GitHub allows at most 10 minutes
MAX_RETRY_WAIT_S = 60.0
MAX_FILES = 3000
ANNOTATIONS_PER_REQUEST = 50  # hard GitHub limit per check-run create or update call


class GitHubError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"GitHub API {status}: {message}")
        self.status = status
        self.message = message


@dataclass(frozen=True)
class PullRequest:
    number: int
    head_sha: str
    base_sha: str
    base_ref: str
    head_repo: str | None  # None when the fork was deleted
    base_repo: str
    draft: bool
    state: str

    @property
    def is_fork(self) -> bool:
        return self.head_repo != self.base_repo


@dataclass(frozen=True)
class Comparison:
    merge_base: str
    ahead_by: int
    behind_by: int
    files: tuple[str, ...]  # changed paths (renames contribute the new path)
    renamed: tuple[tuple[str, str], ...]  # (previous path, new path)


class GitHubClient:
    def __init__(
        self,
        app_id: int,
        private_key: str,
        api_url: str = "https://api.github.com",
        http: httpx.Client | None = None,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
        max_retries: int = 5,
    ) -> None:
        self.app_id = app_id
        self._key = private_key
        self.api_url = api_url.rstrip("/")
        self._http = http or httpx.Client(timeout=30.0)
        self._clock = clock
        self._sleep = sleep
        self._max_retries = max_retries
        self._tokens: dict[tuple[int, str], tuple[str, float]] = {}
        self._token_lock = threading.Lock()
        self._write_locks: defaultdict[int, threading.Lock] = defaultdict(threading.Lock)

    # ---- authentication --------------------------------------------------------------------

    def app_jwt(self) -> str:
        now = int(self._clock())
        payload = {"iat": now - 60, "exp": now + JWT_LIFETIME_S, "iss": str(self.app_id)}
        return jwt.encode(payload, self._key, algorithm="RS256")

    def installation_token(
        self,
        installation_id: int,
        *,
        permissions: dict[str, str] | None = None,
        repositories: list[str] | None = None,
    ) -> str:
        """A cached installation token; ``permissions``/``repositories`` narrow it for git fetch."""
        scope = repr((sorted((permissions or {}).items()), sorted(repositories or [])))
        key = (installation_id, scope)
        with self._token_lock:
            cached = self._tokens.get(key)
            if cached and cached[1] - self._clock() > TOKEN_REFRESH_MARGIN_S:
                return cached[0]
            body: dict[str, Any] = {}
            if permissions:
                body["permissions"] = permissions
            if repositories:
                body["repositories"] = repositories
            resp = self._send(
                "POST",
                f"/app/installations/{installation_id}/access_tokens",
                auth=("app", None),
                json=body or None,
            )
            data = resp.json()
            expires = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00")).astimezone(
                UTC
            )
            self._tokens[key] = (data["token"], expires.timestamp())
            return str(data["token"])

    def _auth_header(self, auth: tuple[str, int | None]) -> str:
        kind, installation_id = auth
        if kind == "app":
            return f"Bearer {self.app_jwt()}"
        assert installation_id is not None
        return f"Bearer {self.installation_token(installation_id)}"

    # ---- transport with retries ------------------------------------------------------------

    def _send(
        self,
        method: str,
        path: str,
        *,
        auth: tuple[str, int | None],
        json: Any = None,
        params: dict[str, Any] | None = None,
        accept: str = "application/vnd.github+json",
        allow_404: bool = False,
    ) -> httpx.Response:
        url = path if path.startswith("http") else f"{self.api_url}{path}"
        refreshed = False
        for attempt in range(self._max_retries + 1):
            headers = {
                "Authorization": self._auth_header(auth),
                "Accept": accept,
                "X-GitHub-Api-Version": API_VERSION,
            }
            try:
                resp = self._http.request(method, url, headers=headers, json=json, params=params)
            except httpx.TransportError as exc:
                if attempt == self._max_retries:
                    raise GitHubError(0, f"network error: {exc}") from exc
                self._sleep(min(2.0**attempt, MAX_RETRY_WAIT_S))
                continue

            if resp.status_code < 400 or (resp.status_code == 404 and allow_404):
                return resp
            if resp.status_code == 401 and auth[0] == "installation" and not refreshed:
                refreshed = True  # the token was revoked or expired early: mint a new one once
                with self._token_lock:
                    self._tokens = {k: v for k, v in self._tokens.items() if k[0] != auth[1]}
                continue
            wait = self._retry_wait(resp, attempt)
            if wait is None or attempt == self._max_retries:
                raise GitHubError(resp.status_code, _message(resp))
            self._sleep(wait)
        raise GitHubError(
            0, "retries exhausted"
        )  # pragma: no cover (loop always returns or raises)

    def _retry_wait(self, resp: httpx.Response, attempt: int) -> float | None:
        """Seconds to wait before retrying, or None if this error is not retryable."""
        status = resp.status_code
        if status >= 500:
            return min(2.0**attempt, MAX_RETRY_WAIT_S)
        if status in (403, 429):
            retry_after = resp.headers.get("retry-after")
            if retry_after and retry_after.isdigit():
                return min(float(retry_after), MAX_RETRY_WAIT_S)
            if resp.headers.get("x-ratelimit-remaining") == "0":
                reset = float(resp.headers.get("x-ratelimit-reset", 0))
                return min(max(reset - self._clock(), 1.0), MAX_RETRY_WAIT_S)
            if status == 429 or "secondary rate limit" in _message(resp).lower():
                return min(2.0**attempt * 5, MAX_RETRY_WAIT_S)
        return None

    def _read(self, installation_id: int, path: str, **kw: Any) -> httpx.Response:
        return self._send("GET", path, auth=("installation", installation_id), **kw)

    def _write(self, installation_id: int, method: str, path: str, **kw: Any) -> httpx.Response:
        with self._write_locks[installation_id]:
            return self._send(method, path, auth=("installation", installation_id), **kw)

    # ---- repository content ----------------------------------------------------------------

    def get_file(self, installation_id: int, repo: str, path: str, ref: str) -> str | None:
        """File text at ``ref``, or None if it does not exist."""
        resp = self._read(
            installation_id,
            f"/repos/{repo}/contents/{path}",
            params={"ref": ref},
            accept="application/vnd.github.raw+json",
            allow_404=True,
        )
        if resp.status_code == 404:
            return None
        return resp.text

    # ---- pull requests and commits ---------------------------------------------------------

    def get_pull_request(self, installation_id: int, repo: str, number: int) -> PullRequest:
        data = self._read(installation_id, f"/repos/{repo}/pulls/{number}").json()
        return _pull_request(data, number)

    def pulls_for_commit(self, installation_id: int, repo: str, sha: str) -> list[PullRequest]:
        """Pull requests that contain a commit; how a re-run finds a fork pull request."""
        data = self._read(
            installation_id, f"/repos/{repo}/commits/{sha}/pulls", params={"per_page": 30}
        ).json()
        return [_pull_request(item) for item in data]

    def compare(self, installation_id: int, repo: str, base: str, head: str) -> Comparison:
        files: list[str] = []
        renamed: list[tuple[str, str]] = []
        merge_base, ahead, behind = base, 0, 0
        for page in range(1, MAX_FILES // 100 + 1):
            data = self._read(
                installation_id,
                f"/repos/{repo}/compare/{base}...{head}",
                params={"per_page": 100, "page": page},
            ).json()
            if page == 1:
                merge_base = data["merge_base_commit"]["sha"]
                ahead, behind = data["ahead_by"], data["behind_by"]
            batch = data.get("files", [])
            for f in batch:
                files.append(f["filename"])
                if f.get("previous_filename"):
                    renamed.append((f["previous_filename"], f["filename"]))
            if len(batch) < 100:
                break
        return Comparison(merge_base, ahead, behind, tuple(files), tuple(renamed))

    # ---- check runs -------------------------------------------------------------------------

    def create_check_run(
        self,
        installation_id: int,
        repo: str,
        *,
        name: str,
        head_sha: str,
        external_id: str,
        title: str,
        summary: str,
    ) -> int:
        body = {
            "name": name,
            "head_sha": head_sha,
            "external_id": external_id,
            "status": "in_progress",
            "started_at": _now(),
            "output": {"title": title, "summary": summary},
        }
        return int(
            self._write(installation_id, "POST", f"/repos/{repo}/check-runs", json=body).json()[
                "id"
            ]
        )

    def update_check_run(
        self,
        installation_id: int,
        repo: str,
        check_run_id: int,
        *,
        title: str,
        summary: str,
        text: str | None = None,
        conclusion: str | None = None,
        annotations: list[dict[str, Any]] | None = None,
    ) -> None:
        """Update a check run. At most 50 annotations per call; the caller batches."""
        if annotations and len(annotations) > ANNOTATIONS_PER_REQUEST:
            raise ValueError("a single check-run request carries at most 50 annotations")
        output: dict[str, Any] = {"title": title, "summary": summary}
        if text:
            output["text"] = text
        if annotations:
            output["annotations"] = annotations
        body: dict[str, Any] = {"output": output}
        if conclusion:
            body.update(status="completed", conclusion=conclusion, completed_at=_now())
        self._write(installation_id, "PATCH", f"/repos/{repo}/check-runs/{check_run_id}", json=body)

    # ---- pull request comments -------------------------------------------------------------

    def list_comments(self, installation_id: int, repo: str, number: int) -> list[dict[str, Any]]:
        comments: list[dict[str, Any]] = []
        for page in range(1, 11):
            batch = self._read(
                installation_id,
                f"/repos/{repo}/issues/{number}/comments",
                params={"per_page": 100, "page": page},
            ).json()
            comments += batch
            if len(batch) < 100:
                break
        return comments

    def create_comment(self, installation_id: int, repo: str, number: int, body: str) -> int:
        resp = self._write(
            installation_id, "POST", f"/repos/{repo}/issues/{number}/comments", json={"body": body}
        )
        return int(resp.json()["id"])

    def update_comment(self, installation_id: int, repo: str, comment_id: int, body: str) -> None:
        self._write(
            installation_id,
            "PATCH",
            f"/repos/{repo}/issues/comments/{comment_id}",
            json={"body": body},
        )


def _pull_request(pr: dict[str, Any], number: int | None = None) -> PullRequest:
    head_repo = (pr["head"].get("repo") or {}).get("full_name")
    return PullRequest(
        number=number if number is not None else int(pr["number"]),
        head_sha=pr["head"]["sha"],
        base_sha=pr["base"]["sha"],
        base_ref=pr["base"]["ref"],
        head_repo=head_repo,
        base_repo=pr["base"]["repo"]["full_name"],
        draft=bool(pr.get("draft")),
        state=pr["state"],
    )


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _message(resp: httpx.Response) -> str:
    try:
        return str(resp.json().get("message", resp.text))[:300]
    except ValueError:
        return resp.text[:300]
