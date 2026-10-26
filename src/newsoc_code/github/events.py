"""Turn GitHub webhook payloads into actions for newsoc.

This module is pure: no database, no network. ``parse_event`` reads only the fields it needs,
treats the payload as untrusted (a payload that is signed can still be unexpected in shape, for
example after a GitHub schema change), and returns an empty list for anything it does not act on.

Deliberate choices:
- Draft pull requests are not scanned until they are marked ready for review.
- A pull request's check is requested again through ``check_run``/``check_suite``
  ``rerequested``. When GitHub does not say which pull request (fork pull requests), the
  action carries no pull request number and the worker resolves it.
- Only pushes to the default branch are scanned (they warm the baseline cache; they do not gate).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from newsoc_code.db.models import Trigger

Handler = Callable[[dict[str, Any], int | None, str], "Parsed"]

SCAN_PR_ACTIONS = frozenset({"opened", "synchronize", "reopened", "ready_for_review"})


@dataclass(frozen=True)
class RepoRef:
    id: int
    full_name: str
    default_branch: str
    owner: str
    owner_type: str
    installation_id: int


@dataclass(frozen=True)
class ScanRequest:
    repo: RepoRef
    trigger: Trigger
    head_sha: str
    pr_number: int | None = None
    base_sha: str | None = None
    base_ref: str | None = None
    is_fork: bool = False


@dataclass(frozen=True)
class CancelPullRequest:
    """The pull request was closed: stop work on it."""

    repo: RepoRef
    pr_number: int


@dataclass(frozen=True)
class InstallationChange:
    installation_id: int
    account_login: str
    account_type: str
    action: str  # created | deleted | suspend | unsuspend
    repos: tuple[tuple[int, str], ...] = ()  # (id, full_name)


@dataclass(frozen=True)
class RepositoriesChange:
    installation_id: int
    account_login: str
    added: tuple[tuple[int, str], ...] = ()
    removed: tuple[tuple[int, str], ...] = ()


Action = ScanRequest | CancelPullRequest | InstallationChange | RepositoriesChange


@dataclass(frozen=True)
class Parsed:
    actions: list[Action] = field(default_factory=list)
    note: str = ""  # why nothing happened, for logs


def _get(obj: Any, *path: str) -> Any:
    for key in path:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def _repo_ref(payload: dict[str, Any]) -> RepoRef | None:
    repo = payload.get("repository")
    installation_id = _get(payload, "installation", "id")
    if not isinstance(repo, dict) or not isinstance(installation_id, int):
        return None
    try:
        return RepoRef(
            id=int(repo["id"]),
            full_name=str(repo["full_name"]),
            default_branch=str(repo.get("default_branch") or "main"),
            owner=str(_get(repo, "owner", "login") or repo["full_name"].split("/")[0]),
            owner_type=str(_get(repo, "owner", "type") or "User"),
            installation_id=installation_id,
        )
    except (KeyError, TypeError, ValueError):
        return None


def _repos(items: Any) -> tuple[tuple[int, str], ...]:
    out = []
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict) and isinstance(item.get("id"), int) and item.get("full_name"):
            out.append((item["id"], str(item["full_name"])))
    return tuple(out)


def parse_event(
    event: str, payload: dict[str, Any], *, app_id: int | None = None, check_name: str
) -> Parsed:
    handler = _HANDLERS.get(event)
    if handler is None:
        return Parsed(note=f"event {event!r} is not handled")
    return handler(payload, app_id, check_name)


def _pull_request(payload: dict[str, Any], app_id: int | None, check_name: str) -> Parsed:
    action = payload.get("action")
    pr = payload.get("pull_request")
    repo = _repo_ref(payload)
    if repo is None or not isinstance(pr, dict):
        return Parsed(note="pull_request payload without repository, installation or pull request")
    number = pr.get("number")
    if not isinstance(number, int):
        return Parsed(note="pull_request without a number")

    if action == "closed":
        return Parsed([CancelPullRequest(repo, number)])
    if action not in SCAN_PR_ACTIONS:
        return Parsed(note=f"pull_request action {action!r} is not scanned")
    if pr.get("draft") and action != "ready_for_review":
        return Parsed(note="draft pull request; scanned when marked ready for review")

    head_sha, base_sha = _get(pr, "head", "sha"), _get(pr, "base", "sha")
    if not isinstance(head_sha, str) or not head_sha:
        return Parsed(note="pull_request without a head commit")
    head_repo = _get(pr, "head", "repo", "full_name")
    base_repo = _get(pr, "base", "repo", "full_name") or repo.full_name
    return Parsed(
        [
            ScanRequest(
                repo=repo,
                trigger=Trigger.PULL_REQUEST,
                head_sha=head_sha,
                pr_number=number,
                base_sha=base_sha if isinstance(base_sha, str) else None,
                base_ref=_get(pr, "base", "ref"),
                is_fork=head_repo != base_repo,  # a deleted fork (None) counts as a fork
            )
        ]
    )


def _push(payload: dict[str, Any], app_id: int | None, check_name: str) -> Parsed:
    repo = _repo_ref(payload)
    if repo is None:
        return Parsed(note="push payload without repository or installation")
    if payload.get("deleted"):
        return Parsed(note="branch deleted")
    if payload.get("ref") != f"refs/heads/{repo.default_branch}":
        return Parsed(note="push to a branch other than the default branch")
    after = payload.get("after")
    if not isinstance(after, str) or set(after) == {"0"}:
        return Parsed(note="push without a head commit")
    return Parsed([ScanRequest(repo=repo, trigger=Trigger.PUSH, head_sha=after)])


def _merge_group(payload: dict[str, Any], app_id: int | None, check_name: str) -> Parsed:
    if payload.get("action") != "checks_requested":
        return Parsed(note=f"merge_group action {payload.get('action')!r} is not scanned")
    repo = _repo_ref(payload)
    group = payload.get("merge_group")
    if repo is None or not isinstance(group, dict) or not isinstance(group.get("head_sha"), str):
        return Parsed(note="merge_group payload without repository or head commit")
    return Parsed(
        [
            ScanRequest(
                repo=repo,
                trigger=Trigger.MERGE_GROUP,
                head_sha=group["head_sha"],
                base_sha=group.get("base_sha"),
                base_ref=group.get("base_ref"),
            )
        ]
    )


def _rerequested(key: str) -> Handler:
    def parse(payload: dict[str, Any], app_id: int | None, check_name: str) -> Parsed:
        if payload.get("action") != "rerequested":
            return Parsed(note=f"{key} action {payload.get('action')!r} is not handled")
        repo = _repo_ref(payload)
        obj = payload.get(key)
        if repo is None or not isinstance(obj, dict):
            return Parsed(note=f"{key} payload without repository or {key}")
        if key == "check_run" and obj.get("name") != check_name:
            return Parsed(note="rerequest for another check")
        if app_id is not None and _get(obj, "app", "id") != app_id:
            return Parsed(note=f"rerequest for another app's {key}")
        head_sha = obj.get("head_sha")
        if not isinstance(head_sha, str) or not head_sha:
            return Parsed(note=f"{key} without a head commit")

        prs = [p for p in obj.get("pull_requests") or [] if isinstance(p, dict)]
        requests: list[Action] = []
        for pr in prs:
            if not isinstance(pr.get("number"), int):
                continue
            head_id, base_id = _get(pr, "head", "repo", "id"), _get(pr, "base", "repo", "id")
            requests.append(
                ScanRequest(
                    repo=repo,
                    trigger=Trigger.PULL_REQUEST,
                    head_sha=head_sha,
                    pr_number=pr["number"],
                    base_sha=_get(pr, "base", "sha"),
                    base_ref=_get(pr, "base", "ref"),
                    is_fork=head_id != base_id,
                )
            )
        # GitHub lists no pull requests for fork pull requests; the worker looks the PR up.
        return Parsed(requests or [ScanRequest(repo, Trigger.RERUN, head_sha)])

    return parse


def _installation(payload: dict[str, Any], app_id: int | None, check_name: str) -> Parsed:
    inst = payload.get("installation")
    action = payload.get("action")
    if not isinstance(inst, dict) or not isinstance(inst.get("id"), int):
        return Parsed(note="installation payload without an installation")
    if action not in {"created", "deleted", "suspend", "unsuspend"}:
        return Parsed(note=f"installation action {action!r} is not handled")
    return Parsed(
        [
            InstallationChange(
                installation_id=inst["id"],
                account_login=str(_get(inst, "account", "login") or "unknown"),
                account_type=str(_get(inst, "account", "type") or "User"),
                action=action,
                repos=_repos(payload.get("repositories")),
            )
        ]
    )


def _installation_repositories(payload: dict[str, Any], app_id: int | None, _: str) -> Parsed:
    inst = payload.get("installation")
    if not isinstance(inst, dict) or not isinstance(inst.get("id"), int):
        return Parsed(note="installation_repositories payload without an installation")
    return Parsed(
        [
            RepositoriesChange(
                installation_id=inst["id"],
                account_login=str(_get(inst, "account", "login") or "unknown"),
                added=_repos(payload.get("repositories_added")),
                removed=_repos(payload.get("repositories_removed")),
            )
        ]
    )


def _ping(payload: dict[str, Any], app_id: int | None, check_name: str) -> Parsed:
    return Parsed(note="ping")


_HANDLERS: dict[str, Handler] = {
    "ping": _ping,
    "pull_request": _pull_request,
    "push": _push,
    "merge_group": _merge_group,
    "check_run": _rerequested("check_run"),
    "check_suite": _rerequested("check_suite"),
    "installation": _installation,
    "installation_repositories": _installation_repositories,
}
