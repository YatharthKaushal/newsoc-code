"""Webhook payloads shaped like GitHub's: the fields newsoc reads, plus some realistic noise."""

from __future__ import annotations

from typing import Any

APP_ID = 424242
INSTALLATION_ID = 99
REPO_ID = 1001
BASE_SHA = "b" * 40
HEAD_SHA = "a" * 40


def repository(
    full_name: str = "acme/app", repo_id: int = REPO_ID, default_branch: str = "main"
) -> dict[str, Any]:
    owner, name = full_name.split("/")
    return {
        "id": repo_id,
        "name": name,
        "full_name": full_name,
        "private": True,
        "default_branch": default_branch,
        "owner": {"login": owner, "type": "Organization", "id": 5},
    }


def _common(repo: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "repository": repo or repository(),
        "installation": {"id": INSTALLATION_ID, "node_id": "MDIzOkluc3RhbGxhdGlvbjk5"},
        "sender": {"login": "octocat", "type": "User"},
    }


def pull_request(
    action: str = "opened",
    *,
    number: int = 7,
    head_sha: str = HEAD_SHA,
    base_sha: str = BASE_SHA,
    draft: bool = False,
    from_fork: bool = False,
    fork_deleted: bool = False,
    repo_name: str = "acme/app",
) -> dict[str, Any]:
    head_repo: dict[str, Any] | None = repository(
        "contrib/app" if from_fork else repo_name, 2002 if from_fork else REPO_ID
    )
    if fork_deleted:
        head_repo = None
    return {
        "action": action,
        "number": number,
        "pull_request": {
            "number": number,
            "state": "closed" if action == "closed" else "open",
            "draft": draft,
            "title": "Add search endpoint",
            "head": {"ref": "feature", "sha": head_sha, "repo": head_repo},
            "base": {"ref": "main", "sha": base_sha, "repo": repository(repo_name)},
        },
        **_common(repository(repo_name)),
    }


def push(
    ref: str = "refs/heads/main", after: str = HEAD_SHA, *, deleted: bool = False
) -> dict[str, Any]:
    return {
        "ref": ref,
        "before": BASE_SHA,
        "after": "0" * 40 if deleted else after,
        "deleted": deleted,
        "created": False,
        "forced": False,
        "commits": [],
        **_common(),
    }


def merge_group(action: str = "checks_requested") -> dict[str, Any]:
    return {
        "action": action,
        "merge_group": {
            "head_sha": "c" * 40,
            "head_ref": "refs/heads/gh-readonly-queue/main/pr-7-aaaa",
            "base_sha": BASE_SHA,
            "base_ref": "refs/heads/main",
        },
        **_common(),
    }


def check_run_rerequested(
    *, name: str = "newsoc/security", app_id: int = APP_ID, prs: list[int] | None = None
) -> dict[str, Any]:
    pulls = [
        {
            "number": n,
            "head": {"ref": "feature", "sha": HEAD_SHA, "repo": {"id": REPO_ID}},
            "base": {"ref": "main", "sha": BASE_SHA, "repo": {"id": REPO_ID}},
        }
        for n in (prs if prs is not None else [7])
    ]
    return {
        "action": "rerequested",
        "check_run": {
            "id": 555,
            "name": name,
            "head_sha": HEAD_SHA,
            "app": {"id": app_id, "slug": "newsoc-dev"},
            "pull_requests": pulls,
        },
        **_common(),
    }


def check_suite_rerequested(
    *, app_id: int = APP_ID, prs: list[int] | None = None
) -> dict[str, Any]:
    run = check_run_rerequested(app_id=app_id, prs=prs)
    suite = {k: run["check_run"][k] for k in ("head_sha", "app", "pull_requests")}
    return {"action": "rerequested", "check_suite": {"id": 77, **suite}, **_common()}


def installation(
    action: str = "created", repos: list[tuple[int, str]] | None = None
) -> dict[str, Any]:
    repos = repos if repos is not None else [(REPO_ID, "acme/app"), (1002, "acme/other")]
    return {
        "action": action,
        "installation": {
            "id": INSTALLATION_ID,
            "account": {"login": "acme", "type": "Organization"},
        },
        "repositories": [{"id": i, "name": n.split("/")[1], "full_name": n} for i, n in repos],
        "sender": {"login": "octocat"},
    }


def installation_repositories(
    *, added: list[tuple[int, str]] | None = None, removed: list[tuple[int, str]] | None = None
) -> dict[str, Any]:
    def fmt(items: list[tuple[int, str]] | None) -> list[dict[str, Any]]:
        return [{"id": i, "full_name": n} for i, n in items or []]

    return {
        "action": "added" if added else "removed",
        "installation": {
            "id": INSTALLATION_ID,
            "account": {"login": "acme", "type": "Organization"},
        },
        "repositories_added": fmt(added),
        "repositories_removed": fmt(removed),
    }
