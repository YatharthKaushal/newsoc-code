"""The whole job pipeline: real Postgres, real queue and worker, real git fetches from a local
remote, a stateful fake GitHub API, and fake scanners that read the real checked-out files."""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime, timedelta

import pytest
from fake_scanners import BlockingRunner, CrashingScanner
from gitremote import git
from pipeline_harness import ENFORCE, OBSERVE, REPO_ID, VULN, Harness
from sqlalchemy import select, update

from newsoc_code.db.models import BaselineRow, ScanJob, ScannerRun, Trigger
from newsoc_code.queue import jobs
from newsoc_code.report.render import COMMENT_MARKER

pytestmark = pytest.mark.pg


# ---- the happy path --------------------------------------------------------------------------


def test_clean_pull_request_gets_a_passing_check_and_one_comment(h: Harness) -> None:
    base = h.base_commit()
    head = h.branch_commit({"feature.js": "const b = 2;\n"})
    h.gh.set_policy(ENFORCE)
    job_id = h.queue_pr(7, head, base)

    h.run()

    check = h.gh.check
    assert (check["name"], check["head_sha"], check["status"]) == (
        "newsoc/security",
        head,
        "completed",
    )
    assert check["conclusion"] == "success"
    assert check["external_id"] == str(job_id)
    [comment] = h.gh.comments.values()
    assert COMMENT_MARKER in comment["body"] and comment["pr"] == 7

    job = h.job(job_id)
    assert (job.status, job.conclusion, job.mode, job.attempt) == ("done", "success", "enforce", 1)
    assert job.check_run_id == check["id"]
    with h.db() as s:
        runs = list(s.scalars(select(ScannerRun).where(ScannerRun.job_id == job_id)))
    assert [(r.scanner, r.status) for r in runs] == [("marker-sast", "ok")]
    assert h.leftovers() == []  # the checkout is deleted


def test_a_new_vulnerability_fails_the_check_in_enforce_mode(h: Harness) -> None:
    base = h.base_commit()
    head = h.branch_commit({"bad.js": VULN})
    h.gh.set_policy(ENFORCE)
    job_id = h.queue_pr(7, head, base)

    h.run()

    check = h.gh.check
    assert check["conclusion"] == "failure"
    [note] = check["annotations"]
    assert (note["path"], note["start_line"], note["annotation_level"]) == ("bad.js", 1, "failure")
    [finding] = h.findings(job_id)
    assert (finding.outcome, finding.path, finding.rule_id) == (
        "blocked",
        "bad.js",
        "fake.marker-vuln",
    )
    [comment] = h.gh.comments.values()
    assert "bad.js" in comment["body"]


def test_observe_mode_reports_a_vulnerability_without_failing(h: Harness) -> None:
    base = h.base_commit()
    head = h.branch_commit({"bad.js": VULN})
    h.gh.set_policy(OBSERVE)
    job_id = h.queue_pr(7, head, base)

    h.run()

    assert h.gh.check["conclusion"] == "neutral"
    assert [f.outcome for f in h.findings(job_id)] == ["would_block"]


def test_a_repository_without_a_policy_runs_in_observe_mode(h: Harness) -> None:
    base = h.base_commit()
    head = h.branch_commit({"bad.js": VULN})
    job_id = h.queue_pr(7, head, base)  # no .secpolicy.yml anywhere

    h.run()

    assert h.gh.check["conclusion"] == "neutral"
    assert h.job(job_id).mode == "observe"


# ---- the policy comes from the base branch ---------------------------------------------------


def test_a_pull_request_cannot_loosen_its_own_policy(h: Harness) -> None:
    base = h.base_commit()
    head = h.branch_commit({"bad.js": VULN, ".secpolicy.yml": OBSERVE})  # the PR tries to opt out
    h.gh.set_policy(ENFORCE, ref="main")
    h.queue_pr(7, head, base)

    h.run()

    assert h.gh.check["conclusion"] == "failure"  # the base branch's policy applied
    assert set(h.gh.contents_refs) == {"main"}  # the policy was never read from the head
    assert "takes effect after it is merged" in h.gh.check["summary"]


# ---- new findings only -----------------------------------------------------------------------


def test_findings_that_already_exist_on_the_base_are_not_new(h: Harness) -> None:
    base = h.base_commit({"old.js": VULN})
    # The PR edits the same file and shifts the vulnerable line down.
    head = h.branch_commit({"old.js": "// header\n// header\n" + VULN})
    h.gh.set_policy(ENFORCE)
    job_id = h.queue_pr(7, head, base)

    h.run()

    assert h.gh.check["conclusion"] == "success"
    assert [f.outcome for f in h.findings(job_id)] == ["baselined"]
    assert len(h.sast.contexts) == 2  # head, then a scan of the base to find the baseline


def test_default_branch_pushes_fill_the_baseline_cache_that_pull_requests_reuse(h: Harness) -> None:
    base = h.base_commit({"old.js": VULN})
    h.gh.set_policy(ENFORCE)
    push_id = h.enqueue(trigger=Trigger.PUSH, head_sha=base)

    h.run()

    assert h.job(push_id).status == "done"
    assert h.gh.check_runs == {} and h.gh.comments == {}  # a push never gates or comments
    assert h.sast.contexts[0].scope is None  # the whole tree was scanned
    with h.db() as s:
        [row] = list(s.scalars(select(BaselineRow)))
    assert row.commit_sha == base and len(row.fingerprints) == 1

    head = h.branch_commit({"old.js": "// moved\n" + VULN})
    h.queue_pr(7, head, base)
    before = len(h.sast.contexts)
    h.run()

    assert h.gh.check["conclusion"] == "success"
    assert len(h.sast.contexts) == before + 1  # only the head was scanned: the baseline was cached


def test_an_incomplete_baseline_is_not_cached(h: Harness) -> None:
    base = h.base_commit({"old.js": VULN})
    h.extra_adapters.append(CrashingScanner())
    h.enqueue(trigger=Trigger.PUSH, head_sha=base)

    h.run()

    with h.db() as s:
        assert (
            list(s.scalars(select(BaselineRow))) == []
        )  # a failed scanner means no trusted baseline


# ---- pull requests that are no longer worth scanning -----------------------------------------


def test_a_pull_request_that_moved_on_is_dropped_without_a_check(h: Harness) -> None:
    base = h.base_commit()
    old = h.branch_commit({"a.js": "1\n"})
    new = h.branch_commit({"a.js": "2\n"})
    h.gh.add_pull(7, new, base)  # GitHub already shows the newer commit
    job_id = h.enqueue(
        trigger=Trigger.PULL_REQUEST, pr_number=7, head_sha=old, base_sha=base, base_ref="main"
    )

    h.run()

    assert h.job(job_id).status == "superseded"
    assert h.gh.check_runs == {}


def test_a_closed_pull_request_is_dropped(h: Harness) -> None:
    base = h.base_commit()
    head = h.branch_commit({"a.js": "1\n"})
    job_id = h.queue_pr(7, head, base, state="closed")

    h.run()

    assert h.job(job_id).status == "superseded" and h.gh.check_runs == {}


# ---- failures: retry, fail closed, never leave a check hanging -------------------------------


def test_a_transient_github_error_is_retried_and_the_check_stays_open(h: Harness) -> None:
    base = h.base_commit()
    head = h.branch_commit({"a.js": "1\n"})
    h.gh.set_policy(ENFORCE)
    job_id = h.queue_pr(7, head, base)
    h.gh.fail("GET", r"/compare/", 502, times=3)  # one request plus its two retries

    h.run()

    job = h.job(job_id)
    assert (job.status, job.attempt) == ("queued", 1)
    assert job.run_after > datetime.now(UTC)  # backing off
    assert h.gh.check["status"] == "in_progress" and "try again" in h.gh.check["summary"]
    assert h.leftovers() == []

    h.make_due(job_id)
    h.run()

    assert (h.job(job_id).status, h.job(job_id).attempt) == ("done", 2)
    assert h.gh.check["conclusion"] == "success"
    assert len(h.gh.check_runs) == 1  # the same check run was reused


def test_running_out_of_retries_closes_the_check_by_mode(h: Harness) -> None:
    base = h.base_commit()
    head = h.branch_commit({"a.js": "1\n"})
    h.gh.set_policy(ENFORCE)
    job_id = h.queue_pr(7, head, base)
    with h.db() as s:
        s.execute(update(ScanJob).where(ScanJob.id == job_id).values(attempt=2))
        s.commit()
    h.gh.fail("GET", r"/compare/", 502, times=3)

    h.run()

    job = h.job(job_id)
    assert (job.status, job.attempt, job.conclusion) == ("failed", 3, "action_required")
    assert h.gh.check["conclusion"] == "action_required"  # enforce: fail closed
    assert "could not complete" in h.gh.check["title"]


@pytest.mark.parametrize(
    ("policy", "expected"), [(ENFORCE, "action_required"), (OBSERVE, "neutral")]
)
def test_a_permanent_error_fails_closed_only_when_enforcing(
    h: Harness, policy: str, expected: str
) -> None:
    base = h.base_commit()
    head = h.branch_commit({"a.js": "1\n"})
    h.gh.set_policy(policy)
    job_id = h.queue_pr(7, head, base)
    h.gh.fail("GET", r"/compare/", 404)

    h.run()

    assert h.job(job_id).status == "failed"
    assert h.gh.check["conclusion"] == expected
    assert "Not assessed" in h.gh.check["summary"]


def test_an_error_before_the_mode_is_known_fails_closed(h: Harness) -> None:
    base = h.base_commit()
    head = h.branch_commit({"a.js": "1\n"})
    job_id = h.queue_pr(7, head, base)
    h.gh.fail("GET", r"/contents/", 403)  # newsoc may not read the policy file

    h.run()

    assert h.job(job_id).mode is None
    assert h.gh.check["conclusion"] == "action_required"


def test_a_crashed_secrets_scanner_blocks_in_enforce_mode(h: Harness) -> None:
    base = h.base_commit()
    head = h.branch_commit({"a.js": "1\n"})
    h.extra_adapters.append(CrashingScanner())
    h.gh.set_policy(ENFORCE)
    job_id = h.queue_pr(7, head, base)

    h.run()

    assert h.gh.check["conclusion"] == "action_required"
    assert "Not assessed" in h.gh.check["summary"]
    with h.db() as s:
        runs = {r.scanner: r.status for r in s.scalars(select(ScannerRun))}
    assert runs == {"marker-sast": "ok", "marker-secrets": "failed"}
    assert h.job(job_id).status == "done"  # the job worked; the verdict is that it must not merge


def test_a_crashed_scanner_in_observe_mode_does_not_block(h: Harness) -> None:
    base = h.base_commit()
    head = h.branch_commit({"a.js": "1\n"})
    h.extra_adapters.append(CrashingScanner())
    h.gh.set_policy(OBSERVE)
    h.queue_pr(7, head, base)

    h.run()

    assert h.gh.check["conclusion"] == "neutral"


# ---- stopping a job in flight ----------------------------------------------------------------


def run_in_thread(h: Harness) -> threading.Thread:
    errors: list[BaseException] = []

    def target() -> None:
        try:
            h.worker.run_once()
        except BaseException as exc:  # pragma: no cover
            errors.append(exc)

    thread = threading.Thread(target=target)
    thread.start()
    thread.errors = errors  # type: ignore[attr-defined]
    return thread


def start_blocked_scan(
    h: Harness, policy: str = ENFORCE
) -> tuple[int, BlockingRunner, threading.Thread]:
    base = h.base_commit()
    head = h.branch_commit({"a.js": "1\n"})
    h.gh.set_policy(policy)
    h.use_runner(BlockingRunner)  # type: ignore[attr-defined]
    job_id = h.queue_pr(7, head, base)
    thread = run_in_thread(h)
    for _ in range(200):
        if h.runners and getattr(h.runners[-1], "started", None) and h.runners[-1].started.is_set():
            break
        time.sleep(0.05)
    runner = h.runners[-1]
    assert isinstance(runner, BlockingRunner) and runner.started.is_set(), "scan never started"
    return job_id, runner, thread


def test_a_newer_push_cancels_the_scan_in_progress(h: Harness) -> None:
    job_id, _runner, thread = start_blocked_scan(h)
    newer = h.branch_commit({"a.js": "2\n"})
    h.gh.add_pull(7, newer, h.gh.pulls[7]["base"]["sha"])
    with h.db() as s:  # what the webhook does when the author pushes again
        jobs.enqueue(
            s,
            repo_id=REPO_ID,
            trigger=Trigger.PULL_REQUEST,
            pr_number=7,
            head_sha=newer,
            base_sha=h.gh.pulls[7]["base"]["sha"],
            base_ref="main",
        )
        s.commit()

    thread.join(timeout=15)

    assert not thread.is_alive() and not thread.errors  # type: ignore[attr-defined]
    assert h.job(job_id).status == "superseded"  # not overwritten by the dying worker
    assert h.gh.check["conclusion"] == "cancelled"
    assert h.leftovers() == []


def test_a_scan_past_its_time_limit_is_stopped_and_fails_closed(h: Harness) -> None:
    h.settings.job_timeout_s = 1
    job_id, _runner, thread = start_blocked_scan(h)

    thread.join(timeout=15)

    assert not thread.is_alive()
    job = h.job(job_id)
    assert (job.status, job.conclusion) == ("failed", "action_required")
    assert "did not finish within 1 seconds" in h.gh.check["summary"]
    assert h.gh.check["conclusion"] == "action_required"


def test_shutting_down_returns_the_job_to_the_queue_without_cancelling_it(h: Harness) -> None:
    job_id, _runner, thread = start_blocked_scan(h)

    h.worker.request_shutdown()
    thread.join(timeout=15)

    job = h.job(job_id)
    assert (job.status, job.attempt) == ("queued", 1)
    assert h.gh.check["status"] == "in_progress" and "restarting" in h.gh.check["summary"]


# ---- other ways a job starts -----------------------------------------------------------------


def test_a_fork_pull_request_is_scanned_from_its_pull_ref(h: Harness) -> None:
    base = h.base_commit()
    head = h.branch_commit({"bad.js": VULN})
    git(h.remote.bare, "update-ref", "-d", "refs/heads/feature")  # a fork's branch is not here
    h.gh.set_policy(ENFORCE)
    job_id = h.queue_pr(7, head, base, fork=True)

    h.run()

    assert h.job(job_id).is_fork
    assert h.gh.check["conclusion"] == "failure"


def test_a_merge_group_is_checked_against_the_base_branchs_policy(h: Harness) -> None:
    base = h.base_commit()
    head = h.branch_commit({"bad.js": VULN})
    h.gh.set_policy(ENFORCE)
    job_id = h.enqueue(
        trigger=Trigger.MERGE_GROUP, head_sha=head, base_sha=base, base_ref="refs/heads/main"
    )

    h.run()

    assert set(h.gh.contents_refs) == {"main"}
    assert h.gh.check["head_sha"] == head and h.gh.check["conclusion"] == "failure"
    assert h.gh.comments == {}  # there is no pull request to comment on
    assert h.job(job_id).pr_number is None


def test_a_rerun_without_a_pull_request_number_finds_the_pull_request(h: Harness) -> None:
    base = h.base_commit()
    head = h.branch_commit({"a.js": "1\n"})
    h.gh.set_policy(ENFORCE)
    h.gh.add_pull(7, head, base)
    job_id = h.enqueue(trigger=Trigger.RERUN, head_sha=head)

    h.run()

    assert h.job(job_id).pr_number == 7
    assert h.gh.check["conclusion"] == "success"
    assert [c["pr"] for c in h.gh.comments.values()] == [7]


def test_a_rerun_with_no_open_pull_request_does_nothing(h: Harness) -> None:
    h.base_commit()
    head = h.branch_commit({"a.js": "1\n"})
    job_id = h.enqueue(trigger=Trigger.RERUN, head_sha=head)

    h.run()

    assert h.job(job_id).status == "done" and h.gh.check_runs == {}


def test_a_second_run_updates_the_same_comment(h: Harness) -> None:
    base = h.base_commit()
    first = h.branch_commit({"a.js": "1\n"})
    h.gh.set_policy(ENFORCE)
    h.queue_pr(7, first, base)
    h.run()
    [comment_id] = h.gh.comments

    second = h.branch_commit({"bad.js": VULN})
    h.queue_pr(7, second, base)
    h.run()

    assert list(h.gh.comments) == [comment_id]  # updated in place, not duplicated
    assert "bad.js" in h.gh.comments[comment_id]["body"]
    assert len(h.gh.check_runs) == 2  # a check per commit


# ---- credentials -----------------------------------------------------------------------------


def test_the_installation_token_is_narrowed_and_never_reaches_a_container(h: Harness) -> None:
    base = h.base_commit()
    head = h.branch_commit({"a.js": "1\n"})
    h.gh.set_policy(ENFORCE)
    h.queue_pr(7, head, base)

    h.run()

    assert {"permissions": {"contents": "read"}, "repositories": ["app"]} in h.gh.token_bodies
    specs = [spec for runner in h.runners for spec in runner.specs]
    assert specs, "no scanner ran"
    for spec in specs:
        blob = repr((spec.argv, dict(spec.env), spec.mounts))
        assert "ghs_FAKE_TOKEN" not in blob


# ---- recovery --------------------------------------------------------------------------------


def test_the_reaper_retries_a_lost_job_then_closes_its_check(h: Harness) -> None:
    base = h.base_commit()
    head = h.branch_commit({"a.js": "1\n"})
    job_id = h.queue_pr(7, head, base)
    check_id = h.gh.client.create_check_run(
        99,
        "acme/app",
        name="newsoc/security",
        head_sha=head,
        external_id="x",
        title="t",
        summary="s",
    )

    def die_mid_scan() -> None:  # a worker claims the job, records its check, and vanishes
        with h.db() as s:
            claimed = jobs.claim_next(s, "dead-worker", 60)
            assert claimed is not None
            claimed.check_run_id, claimed.mode = check_id, "enforce"
            claimed.locked_until = datetime.now(UTC) - timedelta(seconds=5)
            s.commit()

    die_mid_scan()
    reaped = h.worker.reap()
    assert reaped.requeued == [job_id] and reaped.failed == []
    assert h.gh.check_runs[check_id]["status"] == "in_progress"

    for _ in range(2):  # attempts 2 and 3 are lost as well
        h.make_due(job_id)
        die_mid_scan()
        reaped = h.worker.reap()

    assert [j.id for j in reaped.failed] == [job_id]
    assert h.job(job_id).status == "failed"
    check = h.gh.check_runs[check_id]
    assert (check["status"], check["conclusion"]) == ("completed", "action_required")
