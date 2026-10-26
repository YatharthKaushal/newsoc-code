from __future__ import annotations

from typing import Any

import github_payloads as gh
import pytest

from newsoc_code.db.models import Trigger
from newsoc_code.github.events import (
    CancelPullRequest,
    InstallationChange,
    Parsed,
    RepositoriesChange,
    ScanRequest,
    parse_event,
)

CHECK = "newsoc/security"


def parse(event: str, payload: dict[str, Any], app_id: int | None = gh.APP_ID) -> Parsed:
    return parse_event(event, payload, app_id=app_id, check_name=CHECK)


def only(parsed: Parsed) -> Any:
    assert len(parsed.actions) == 1, parsed
    return parsed.actions[0]


@pytest.mark.parametrize("action", ["opened", "synchronize", "reopened", "ready_for_review"])
def test_pull_request_actions_that_are_scanned(action: str) -> None:
    req = only(parse("pull_request", gh.pull_request(action)))
    assert isinstance(req, ScanRequest)
    assert (req.trigger, req.pr_number, req.head_sha, req.base_sha) == (
        Trigger.PULL_REQUEST,
        7,
        gh.HEAD_SHA,
        gh.BASE_SHA,
    )
    assert req.base_ref == "main" and not req.is_fork
    assert req.repo.id == gh.REPO_ID and req.repo.installation_id == gh.INSTALLATION_ID


@pytest.mark.parametrize(
    "action", ["edited", "labeled", "assigned", "review_requested", "unlabeled"]
)
def test_pull_request_actions_that_are_not_scanned(action: str) -> None:
    parsed = parse("pull_request", gh.pull_request(action))
    assert parsed.actions == [] and "not scanned" in parsed.note


def test_closed_pull_request_cancels_its_work() -> None:
    act = only(parse("pull_request", gh.pull_request("closed")))
    assert isinstance(act, CancelPullRequest) and act.pr_number == 7


def test_drafts_wait_until_ready_for_review() -> None:
    assert parse("pull_request", gh.pull_request("opened", draft=True)).actions == []
    assert parse("pull_request", gh.pull_request("synchronize", draft=True)).actions == []
    ready = parse("pull_request", gh.pull_request("ready_for_review", draft=False))
    assert len(ready.actions) == 1


def test_fork_pull_requests_are_flagged() -> None:
    assert only(parse("pull_request", gh.pull_request(from_fork=True))).is_fork
    assert only(parse("pull_request", gh.pull_request(fork_deleted=True))).is_fork


def test_pull_request_without_installation_is_ignored() -> None:
    payload = gh.pull_request()
    del payload["installation"]
    assert parse("pull_request", payload).actions == []


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p.pop("pull_request"),
        lambda p: p["pull_request"].pop("number"),
        lambda p: p["pull_request"]["head"].pop("sha"),
        lambda p: p.__setitem__("repository", "not-a-dict"),
        lambda p: p["repository"].pop("id"),
        lambda p: p.__setitem__("pull_request", []),
    ],
)
def test_malformed_pull_request_payloads_are_ignored_not_crashed(mutate: Any) -> None:
    payload = gh.pull_request()
    mutate(payload)
    assert parse("pull_request", payload).actions == []


def test_push_to_default_branch_builds_the_baseline() -> None:
    req = only(parse("push", gh.push()))
    assert (req.trigger, req.pr_number, req.head_sha) == (Trigger.PUSH, None, gh.HEAD_SHA)


def test_push_to_other_branches_tags_and_deletions_are_ignored() -> None:
    assert parse("push", gh.push("refs/heads/feature")).actions == []
    assert parse("push", gh.push("refs/tags/v1")).actions == []
    assert parse("push", gh.push(deleted=True)).actions == []


def test_push_honours_a_non_main_default_branch() -> None:
    payload = gh.push("refs/heads/trunk")
    payload["repository"]["default_branch"] = "trunk"
    assert len(parse("push", payload).actions) == 1


def test_merge_group_checks_requested_scans_the_group_head() -> None:
    req = only(parse("merge_group", gh.merge_group()))
    assert (req.trigger, req.head_sha, req.base_sha) == (Trigger.MERGE_GROUP, "c" * 40, gh.BASE_SHA)
    assert req.pr_number is None


def test_merge_group_destroyed_is_ignored() -> None:
    assert parse("merge_group", gh.merge_group("destroyed")).actions == []


def test_rerequested_check_run_reruns_the_pull_request() -> None:
    req = only(parse("check_run", gh.check_run_rerequested()))
    assert (req.trigger, req.pr_number, req.head_sha) == (Trigger.PULL_REQUEST, 7, gh.HEAD_SHA)


def test_rerequested_check_run_for_several_pull_requests() -> None:
    parsed = parse("check_run", gh.check_run_rerequested(prs=[7, 9]))
    assert [a.pr_number for a in parsed.actions] == [7, 9]


def test_rerun_without_pull_requests_is_left_for_the_worker_to_resolve() -> None:
    req = only(parse("check_run", gh.check_run_rerequested(prs=[])))
    assert (req.trigger, req.pr_number) == (Trigger.RERUN, None)


def test_rerun_of_another_check_or_another_app_is_ignored() -> None:
    assert parse("check_run", gh.check_run_rerequested(name="ci/build")).actions == []
    assert parse("check_run", gh.check_run_rerequested(app_id=1)).actions == []
    assert parse("check_suite", gh.check_suite_rerequested(app_id=1)).actions == []


def test_rerequested_check_suite_reruns_the_pull_request() -> None:
    req = only(parse("check_suite", gh.check_suite_rerequested()))
    assert req.pr_number == 7


def test_only_rerequested_check_events_are_handled() -> None:
    payload = gh.check_run_rerequested()
    payload["action"] = "completed"
    assert parse("check_run", payload).actions == []


def test_installation_created_lists_repositories() -> None:
    change = only(parse("installation", gh.installation("created")))
    assert isinstance(change, InstallationChange)
    assert change.action == "created" and change.account_login == "acme"
    assert change.repos == ((gh.REPO_ID, "acme/app"), (1002, "acme/other"))


@pytest.mark.parametrize("action", ["deleted", "suspend", "unsuspend"])
def test_installation_lifecycle_actions(action: str) -> None:
    assert only(parse("installation", gh.installation(action))).action == action


def test_installation_repositories_added_and_removed() -> None:
    added = only(
        parse("installation_repositories", gh.installation_repositories(added=[(5, "a/b")]))
    )
    assert isinstance(added, RepositoriesChange) and added.added == ((5, "a/b"),)
    removed = only(
        parse("installation_repositories", gh.installation_repositories(removed=[(5, "a/b")]))
    )
    assert removed.removed == ((5, "a/b"),)


def test_junk_repository_entries_are_dropped() -> None:
    payload = gh.installation()
    payload["repositories"] = [{"id": "x"}, "nope", {"id": 3}, {"id": 4, "full_name": "a/b"}]
    assert only(parse("installation", payload)).repos == ((4, "a/b"),)


@pytest.mark.parametrize("event", ["ping", "star", "issues", "workflow_run", "deployment", "fork"])
def test_other_events_are_ignored(event: str) -> None:
    assert parse(event, {"zen": "Keep it logically awesome."}).actions == []
