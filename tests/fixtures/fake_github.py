"""A stateful in-memory GitHub REST API (httpx.MockTransport) for pipeline tests.

It speaks only the endpoints newsoc uses, records what was done to it, and computes ``compare``
from a real git repository so tests describe changes by committing, not by writing diffs.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from gitremote import Remote

from newsoc_code.github.client import GitHubClient

APP_ID = 424242
INSTALLATION_ID = 99
API = "https://api.example.test"


def make_private_key() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


class FakeGitHub:
    def __init__(self, remote: Remote, private_key: str, repo: str = "acme/app") -> None:
        self.remote = remote
        self.repo = repo
        self.pulls: dict[int, dict[str, Any]] = {}
        self.files: dict[tuple[str, str], str] = {}  # (ref, path) to text
        self.check_runs: dict[int, dict[str, Any]] = {}
        self.comments: dict[int, dict[str, Any]] = {}
        self.calls: list[tuple[str, str]] = []
        self.contents_refs: list[str] = []
        self.token_bodies: list[dict[str, Any]] = []
        self.faults: list[tuple[str, str, int]] = []  # (method, path regex, status), consumed once
        self._next_id = 1000
        self.client = GitHubClient(
            app_id=APP_ID,
            private_key=private_key,
            api_url=API,
            http=httpx.Client(transport=httpx.MockTransport(self._handle)),
            sleep=lambda _s: None,
            max_retries=2,
        )

    # ---- test setup --------------------------------------------------------------------------

    def add_pull(
        self,
        number: int,
        head_sha: str,
        base_sha: str,
        *,
        base_ref: str = "main",
        fork: bool = False,
        state: str = "open",
        draft: bool = False,
    ) -> None:
        self.remote.pull_ref(number, head_sha)
        head_repo = "contrib/app" if fork else self.repo
        self.pulls[number] = {
            "number": number,
            "state": state,
            "draft": draft,
            "head": {"sha": head_sha, "ref": "feature", "repo": {"full_name": head_repo}},
            "base": {"sha": base_sha, "ref": base_ref, "repo": {"full_name": self.repo}},
        }

    def set_policy(self, text: str, ref: str = "main") -> None:
        self.files[(ref, ".secpolicy.yml")] = text

    def fail(self, method: str, path_regex: str, status: int, times: int = 1) -> None:
        self.faults += [(method, path_regex, status)] * times

    # ---- what happened -----------------------------------------------------------------------

    @property
    def check(self) -> dict[str, Any]:
        assert len(self.check_runs) == 1, f"expected one check run, got {len(self.check_runs)}"
        return next(iter(self.check_runs.values()))

    def count(self, method: str, pattern: str) -> int:
        return sum(1 for m, p in self.calls if m == method and re.search(pattern, p))

    # ---- the API -----------------------------------------------------------------------------

    def _id(self) -> int:
        self._next_id += 1
        return self._next_id

    def _handle(self, request: httpx.Request) -> httpx.Response:
        method, path = request.method, request.url.path
        self.calls.append((method, path))
        for i, (m, rx, status) in enumerate(self.faults):
            if m == method and re.search(rx, path):
                del self.faults[i]
                return httpx.Response(status, json={"message": "injected fault"})
        body = json.loads(request.content) if request.content else {}

        for pattern, verb, handler in self._routes():
            if verb == method and (m := re.fullmatch(pattern, path)):
                return handler(request, body, *m.groups())
        return httpx.Response(404, json={"message": f"unhandled {method} {path}"})

    def _routes(self) -> list[tuple[str, str, Callable[..., httpx.Response]]]:
        r = rf"/repos/{re.escape(self.repo)}"
        return [
            (r"/app/installations/(\d+)/access_tokens", "POST", self._token),
            (rf"{r}/pulls/(\d+)", "GET", self._get_pull),
            (rf"{r}/commits/([0-9a-f]{{40}})/pulls", "GET", self._pulls_for_commit),
            (rf"{r}/contents/(.+)", "GET", self._contents),
            (rf"{r}/compare/(.+)\.\.\.(.+)", "GET", self._compare),
            (rf"{r}/check-runs", "POST", self._create_check),
            (rf"{r}/check-runs/(\d+)", "PATCH", self._update_check),
            (rf"{r}/issues/(\d+)/comments", "GET", self._list_comments),
            (rf"{r}/issues/(\d+)/comments", "POST", self._create_comment),
            (rf"{r}/issues/comments/(\d+)", "PATCH", self._update_comment),
        ]

    def _token(self, req: httpx.Request, body: dict[str, Any], _inst: str) -> httpx.Response:
        self.token_bodies.append(body)
        expires = (datetime.now(UTC) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        return httpx.Response(201, json={"token": "ghs_FAKE_TOKEN", "expires_at": expires})

    def _get_pull(self, req: httpx.Request, body: dict[str, Any], number: str) -> httpx.Response:
        pr = self.pulls.get(int(number))
        return httpx.Response(200, json=pr) if pr else httpx.Response(404, json={"message": "nf"})

    def _pulls_for_commit(
        self, req: httpx.Request, body: dict[str, Any], sha: str
    ) -> httpx.Response:
        found = [p for p in self.pulls.values() if p["head"]["sha"] == sha]
        return httpx.Response(200, json=found)

    def _contents(self, req: httpx.Request, body: dict[str, Any], path: str) -> httpx.Response:
        ref = req.url.params.get("ref", "")
        self.contents_refs.append(ref)
        text = self.files.get((ref, path))
        if text is None:
            return httpx.Response(404, json={"message": "Not Found"})
        return httpx.Response(200, text=text)

    def _compare(
        self, req: httpx.Request, body: dict[str, Any], base: str, head: str
    ) -> httpx.Response:
        remote = self.remote
        base_sha = base if re.fullmatch(r"[0-9a-f]{40}", base) else remote_rev(remote, base)
        files = []
        for status, name, previous in remote.changed(base_sha, head):
            entry: dict[str, Any] = {"filename": name, "status": status}
            if previous:
                entry["previous_filename"] = previous
            files.append(entry)
        page = int(req.url.params.get("page", "1"))
        per_page = int(req.url.params.get("per_page", "30"))
        window = files[(page - 1) * per_page : page * per_page]
        return httpx.Response(
            200,
            json={
                "merge_base_commit": {"sha": remote.merge_base(base_sha, head)},
                "ahead_by": remote.ahead_by(base_sha, head),
                "behind_by": remote.ahead_by(head, base_sha),
                "files": window,
            },
        )

    def _create_check(self, req: httpx.Request, body: dict[str, Any], *_: str) -> httpx.Response:
        check_id = self._id()
        self.check_runs[check_id] = {
            "id": check_id,
            "name": body["name"],
            "head_sha": body["head_sha"],
            "external_id": body.get("external_id"),
            "status": body["status"],
            "conclusion": None,
            "title": body["output"]["title"],
            "summary": body["output"]["summary"],
            "annotations": [],
            "updates": 0,
        }
        return httpx.Response(201, json={"id": check_id})

    def _update_check(
        self, req: httpx.Request, body: dict[str, Any], check_id: str
    ) -> httpx.Response:
        check = self.check_runs[int(check_id)]
        check["updates"] += 1
        output = body.get("output", {})
        check["title"] = output.get("title", check["title"])
        check["summary"] = output.get("summary", check["summary"])
        check["annotations"] += output.get("annotations", [])
        if "conclusion" in body:
            check["status"], check["conclusion"] = "completed", body["conclusion"]
        return httpx.Response(200, json={"id": int(check_id)})

    def _list_comments(self, req: httpx.Request, body: dict[str, Any], _n: str) -> httpx.Response:
        return httpx.Response(200, json=list(self.comments.values()))

    def _create_comment(
        self, req: httpx.Request, body: dict[str, Any], number: str
    ) -> httpx.Response:
        cid = self._id()
        self.comments[cid] = {
            "id": cid,
            "body": body["body"],
            "pr": int(number),
            "performed_via_github_app": {"id": APP_ID},
        }
        return httpx.Response(201, json={"id": cid})

    def _update_comment(self, req: httpx.Request, body: dict[str, Any], cid: str) -> httpx.Response:
        if int(cid) not in self.comments:
            return httpx.Response(404, json={"message": "Not Found"})
        self.comments[int(cid)]["body"] = body["body"]
        return httpx.Response(200, json={"id": int(cid)})


def remote_rev(remote: Remote, rev: str) -> str:
    from gitremote import git

    return git(remote.work, "rev-parse", rev)
