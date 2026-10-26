"""Process one scan job from queue to published check.

Order of work (each step is a place the job can be cancelled or fail):

1. Look up the pull request and confirm it is still open and still at the commit we were asked
   to scan. Create the check run ``in_progress`` right away, so a required check never sits at
   "expected".
2. Read ``.secpolicy.yml`` from the **base branch**. A pull request cannot loosen its own gate:
   its head version of the file is never read.
3. Fetch the head commit (and the merge base) with a token limited to this repository's
   contents, outside any container. Scan the head with every applicable scanner.
4. Find the baseline (findings that already exist on the base): from the cache that
   default-branch pushes fill, or by scanning the base.
5. Evaluate the policy, store the findings, publish the check and the pull request comment.

Failure rules:
* A superseded job closes its check as ``cancelled``.
* A transient error (GitHub 5xx, network) is retried a few times with the check left in progress.
* A permanent error, or running out of retries, closes the check with a conclusion that depends
  on the policy mode: ``neutral`` in observe mode, ``action_required`` in enforce mode or when the
  mode is not known yet. ``neutral`` passes a required check, so it is never used to fail closed.
"""

from __future__ import annotations

import hashlib
import logging
import shutil
import threading
import uuid
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session, sessionmaker

from newsoc_code import osvdb
from newsoc_code.config import Settings
from newsoc_code.db.models import (
    BaselineRow,
    FindingRow,
    JobStatus,
    PrComment,
    Repository,
    ScanJob,
    ScannerRun,
    Trigger,
)
from newsoc_code.db.session import session_scope
from newsoc_code.findings import baseline as baselines
from newsoc_code.findings.schema import ScanResult
from newsoc_code.github.checks import publish_result
from newsoc_code.github.client import MAX_FILES, Comparison, GitHubClient, GitHubError
from newsoc_code.github.comments import upsert_summary_comment
from newsoc_code.github.fetch import (
    MAX_HISTORY_DEPTH,
    CheckoutTooLarge,
    StaleHead,
    Workspace,
)
from newsoc_code.policy.engine import Conclusion, PolicyOutcome, evaluate
from newsoc_code.policy.loader import PolicyLoad, load_policy
from newsoc_code.policy.schema import Mode
from newsoc_code.report.render import CHECK_NAME, render_check, render_comment
from newsoc_code.runner.base import Runner
from newsoc_code.scan import default_adapters, rules_version, scan_tree
from newsoc_code.scanners.base import ScanContext, ScannerAdapter, TreeInfo

log = logging.getLogger("newsoc.pipeline")

POLICY_PATH = ".secpolicy.yml"
HEAD_DEPTH_MARGIN = 50
RETRY_DELAYS_S = (30, 120, 300)
KEEP_BASELINES_PER_REPO = 50
PERMANENT_HTTP = frozenset({400, 401, 403, 404, 410, 422})

RunnerFactory = Callable[[threading.Event], Runner]
WorkspaceFactory = Callable[[Path, str, str | None], Workspace]


class Superseded(Exception):
    """A newer commit replaced this one, or the pull request was closed."""


class JobTimeout(Exception):
    """The job exceeded its time limit."""


class Shutdown(Exception):
    """The worker is stopping; the job goes back to the queue."""


class PermanentError(Exception):
    """Retrying will not help; the message is shown to the developer."""


@dataclass
class JobControl:
    """Lets the worker stop a job from another thread (superseded, timed out, shutting down)."""

    cancel: threading.Event = field(default_factory=threading.Event)
    reason: str = "superseded"

    def stop(self, reason: str) -> None:
        self.reason = reason
        self.cancel.set()

    def check(self) -> None:
        if self.cancel.is_set():
            if self.reason == "timeout":
                raise JobTimeout()
            if self.reason == "shutdown":
                raise Shutdown()
            raise Superseded()


@dataclass
class JobView:
    """Plain data copied out of the database so no session is held while scanning."""

    id: int
    repo_id: int
    repo_name: str
    default_branch: str
    installation_id: int
    trigger: Trigger
    pr_number: int | None
    head_sha: str
    base_sha: str | None
    base_ref: str | None
    is_fork: bool
    check_run_id: int | None
    attempt: int


@dataclass
class JobOutcome:
    status: JobStatus  # DONE, FAILED, SUPERSEDED, or QUEUED (retry)
    conclusion: str | None = None
    error: str | None = None
    retry_delay_s: int | None = None


@dataclass
class RunState:
    mode: Mode | None = None
    check_run_id: int | None = None


def fallback_conclusion(mode: Mode | None) -> Conclusion:
    """How to close a check when newsoc itself failed. Never ``neutral`` unless the repository
    is known to be in observe mode, because ``neutral`` passes a required check."""
    return Conclusion.NEUTRAL if mode is Mode.OBSERVE else Conclusion.ACTION_REQUIRED


def scanner_key(
    adapters: Sequence[ScannerAdapter], rules_ver: str | None, osv_snapshot: str
) -> str:
    """Identifies the scanners and data a baseline was produced with. A baseline made with
    other tool versions, another rule pack or another vulnerability snapshot is not comparable."""
    parts = sorted(f"{a.name}={a.pinned_version}" for a in adapters)
    parts += [f"rules={rules_ver}", f"osv={osv_snapshot}"]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]


def _strip_ref(ref: str | None) -> str | None:
    return ref.removeprefix("refs/heads/") if ref else ref


def _scope(files: Iterable[str], tree: TreeInfo) -> tuple[str, ...]:
    """Changed files that exist in this tree (deleted files are in the diff but not on disk)."""
    present = set(tree.files)
    return tuple(sorted(f for f in set(files) if f in present))


class JobProcessor:
    def __init__(
        self,
        *,
        settings: Settings,
        session_factory: sessionmaker[Session],
        github: GitHubClient,
        runner_factory: RunnerFactory,
        workspace_factory: WorkspaceFactory,
        adapters_factory: Callable[[], Sequence[ScannerAdapter]] = default_adapters,
        today: Callable[[], date] = lambda: datetime.now(UTC).date(),
    ) -> None:
        self.settings = settings
        self.sessions = session_factory
        self.github = github
        self.runner_factory = runner_factory
        self.workspace_factory = workspace_factory
        self.adapters_factory = adapters_factory
        self.today = today

    # ---- entry point ------------------------------------------------------------------------

    def run(self, job_id: int, control: JobControl) -> JobOutcome:
        view = self._load(job_id)
        state = RunState(check_run_id=view.check_run_id)
        workdir = self.settings.work_root / f"job-{job_id}-{uuid.uuid4().hex[:8]}"
        try:
            workdir.mkdir(parents=True, mode=0o700)
            return self._execute(view, state, control, workdir)
        except (Superseded, StaleHead) as exc:
            log.info("job %s cancelled: %s", job_id, exc or "superseded")
            self._close_check(
                view, state, "cancelled", "Superseded", "A newer commit replaced this one."
            )
            return JobOutcome(JobStatus.SUPERSEDED)
        except Shutdown:
            self._note(view, state, "newsoc is restarting and will run this scan again.")
            return JobOutcome(JobStatus.QUEUED, error="worker shutting down", retry_delay_s=5)
        except JobTimeout:
            seconds = self.settings.job_timeout_s
            limit = f"{seconds // 60} minutes" if seconds >= 120 else f"{seconds} seconds"
            return self._fail(view, state, f"The scan did not finish within {limit}.")
        except (PermanentError, CheckoutTooLarge) as exc:
            return self._fail(view, state, f"Not assessed: {exc}")
        except Exception as exc:
            if _permanent(exc):
                return self._fail(view, state, f"Not assessed: {exc}")
            log.exception("job %s failed (attempt %s)", job_id, view.attempt)
            if view.attempt < self.settings.max_attempts:
                delay = RETRY_DELAYS_S[min(view.attempt, len(RETRY_DELAYS_S)) - 1]
                self._note(view, state, "newsoc hit a temporary problem and will try again.")
                return JobOutcome(
                    JobStatus.QUEUED, error=f"{type(exc).__name__}: {exc}", retry_delay_s=delay
                )
            return self._fail(view, state, "newsoc could not complete this check (internal error).")
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    # ---- the pipeline -----------------------------------------------------------------------

    def _execute(
        self, view: JobView, state: RunState, control: JobControl, workdir: Path
    ) -> JobOutcome:
        gh, inst, repo = self.github, view.installation_id, view.repo_name
        control.check()

        if view.trigger is Trigger.RERUN and view.pr_number is None:
            pr_number = self._resolve_rerun(view)
            if pr_number is None:
                return JobOutcome(JobStatus.DONE, error="no open pull request for this commit")
            view.pr_number = pr_number

        if view.pr_number is not None:
            pr = gh.get_pull_request(inst, repo, view.pr_number)
            if pr.state != "open":
                return JobOutcome(JobStatus.SUPERSEDED, error="pull request is closed")
            if pr.head_sha != view.head_sha:
                raise Superseded("pull request moved to " + pr.head_sha[:10])
            view.base_sha, view.base_ref, view.is_fork = pr.base_sha, pr.base_ref, pr.is_fork
            self._store_pull_request(view)

        gating = view.trigger is not Trigger.PUSH
        if gating:
            self._ensure_check(view, state)

        loaded: PolicyLoad | None = None
        if gating:
            loaded = self._read_policy(view)
            state.mode = loaded.policy.mode
            self._store_mode(view.id, state.mode)

        comparison = None
        if gating:  # a merge group without a base falls back to the default branch
            comparison = gh.compare(inst, repo, view.base_sha or view.default_branch, view.head_sha)
        control.check()

        adapters = list(self.adapters_factory())
        rules_dir = self.settings.rules_dir
        rules_ver = rules_version(rules_dir) if rules_dir.exists() else None
        snapshot = osvdb.current(self.settings.osv_db_root)
        osv_name = snapshot.name if snapshot else "none"
        key = scanner_key(adapters, rules_ver, osv_name)
        runner = self.runner_factory(control.cancel)

        token = gh.installation_token(
            inst, permissions={"contents": "read"}, repositories=[repo.split("/", 1)[1]]
        )
        ws = self.workspace_factory(workdir / "ws", repo, token)
        ws.init()
        target = f"refs/pull/{view.pr_number}/head" if view.pr_number else view.head_sha
        depth = min(comparison.ahead_by + HEAD_DEPTH_MARGIN, MAX_HISTORY_DEPTH) if comparison else 1
        head_sha = ws.fetch(target, depth=depth, name="head", expect_sha=view.head_sha)
        head_root = ws.checkout(head_sha)
        if comparison:
            ws.fetch(comparison.merge_base, depth=1, name="base")
        control.check()

        notes: list[str] = []
        head_tree = TreeInfo.scan(head_root)
        if head_tree.truncated:
            notes.append("The repository has more files than newsoc scans; some were skipped.")
        scope: tuple[str, ...] | None = None
        if comparison:
            if len(comparison.files) >= MAX_FILES:
                notes.append("The diff is too large to list; the whole tree was scanned.")
            else:
                scope = _scope(comparison.files, head_tree)
        ctx = ScanContext(
            src_root=head_root,
            out_dir=self._out_dir(workdir, "head"),
            tree=head_tree,
            salt=self.settings.salt(),
            rules_dir=rules_dir if rules_dir.exists() else None,
            rules_version=rules_ver,
            osv_db_dir=snapshot or self.settings.osv_db_root,
            commit=head_sha,
            scope=scope,
            gitleaks_mode="git" if comparison else "dir",
            gitleaks_log_opts=(
                ws.merge_base_log_range(comparison.merge_base, head_sha) if comparison else None
            ),
        )
        results = scan_tree(ctx, runner, adapters, self.settings.max_concurrent_scanners)
        control.check()

        if not gating:  # a default-branch push only fills the baseline cache
            self._store_baseline(view, head_sha, key, results)
            self._persist(view, results, None, rules_ver, snapshot)
            return JobOutcome(JobStatus.DONE)

        assert loaded is not None and comparison is not None
        baseline = None
        if loaded.policy.merge.new_findings_only:
            baseline = self._baseline(
                view, ws, comparison, key, rules_ver, adapters, runner, workdir, control, notes
            )
            control.check()

        today = self.today()
        outcome = evaluate(loaded, results, baseline, today)
        if POLICY_PATH in comparison.files:
            notes.append(
                f"This pull request changes {POLICY_PATH}. newsoc applies the version on the "
                "base branch, so the change takes effect after it is merged."
            )
        outcome.notes.extend(notes)
        if snapshot is not None and (warning := _osv_warning(snapshot)):
            outcome.notes.append(warning)

        self._persist(view, results, outcome, rules_ver, snapshot)
        control.check()
        self._publish(view, state, results, outcome, rules_ver)
        return JobOutcome(JobStatus.DONE, conclusion=outcome.conclusion.value)

    # ---- steps ------------------------------------------------------------------------------

    def _resolve_rerun(self, view: JobView) -> int | None:
        prs = self.github.pulls_for_commit(view.installation_id, view.repo_name, view.head_sha)
        open_prs = [p for p in prs if p.state == "open"]
        return open_prs[0].number if open_prs else None

    def _read_policy(self, view: JobView) -> PolicyLoad:
        ref = _strip_ref(view.base_ref) or view.default_branch
        text = self.github.get_file(view.installation_id, view.repo_name, POLICY_PATH, ref)
        return load_policy(text, self.today())

    def _baseline(
        self,
        view: JobView,
        ws: Workspace,
        comparison: Comparison,
        key: str,
        rules_ver: str | None,
        adapters: Sequence[ScannerAdapter],
        runner: Runner,
        workdir: Path,
        control: JobControl,
        notes: list[str],
    ) -> frozenset[str] | None:
        with session_scope(self.sessions) as s:
            cached = s.get(BaselineRow, (view.repo_id, comparison.merge_base, key))
            if cached is not None:
                return frozenset(cached.fingerprints)

        base_root = ws.checkout(comparison.merge_base, workdir / "base")
        base_tree = TreeInfo.scan(base_root)
        previous = [old for old, _new in comparison.renamed]
        ctx = ScanContext(
            src_root=base_root,
            out_dir=self._out_dir(workdir, "base"),
            tree=base_tree,
            salt=self.settings.salt(),
            rules_dir=self.settings.rules_dir if self.settings.rules_dir.exists() else None,
            rules_version=rules_ver,
            osv_db_dir=osvdb.current(self.settings.osv_db_root) or self.settings.osv_db_root,
            commit=comparison.merge_base,
            scope=_scope([*comparison.files, *previous], base_tree),
            gitleaks_mode="dir",
        )
        base_results = scan_tree(ctx, runner, adapters, self.settings.max_concurrent_scanners)
        control.check()
        if baselines.assessed(base_results):
            return baselines.from_results(base_results)
        notes.append(
            "Baseline unavailable: the scan of the base branch was incomplete, so every "
            "finding in this pull request is treated as new."
        )
        return None

    def _store_baseline(self, view: JobView, sha: str, key: str, results: list[ScanResult]) -> None:
        """Remember a full scan of a default-branch commit, if every scanner was trustworthy."""
        if not baselines.assessed(results):
            log.warning(
                "not caching a baseline for %s@%s: scan incomplete", view.repo_name, sha[:10]
            )
            return
        fingerprints: list[Any] = sorted(baselines.from_results(results))
        with session_scope(self.sessions) as s:
            s.execute(
                pg_insert(BaselineRow)
                .values(
                    repo_id=view.repo_id, commit_sha=sha, scanner_key=key, fingerprints=fingerprints
                )
                .on_conflict_do_update(
                    index_elements=["repo_id", "commit_sha", "scanner_key"],
                    set_={"fingerprints": fingerprints},
                )
            )
            keep = list(
                s.scalars(
                    select(BaselineRow.commit_sha)
                    .where(BaselineRow.repo_id == view.repo_id)
                    .order_by(BaselineRow.created_at.desc())
                    .limit(KEEP_BASELINES_PER_REPO)
                )
            )
            s.execute(
                delete(BaselineRow).where(
                    BaselineRow.repo_id == view.repo_id, BaselineRow.commit_sha.not_in(keep)
                )
            )

    def _persist(
        self,
        view: JobView,
        results: list[ScanResult],
        outcome: PolicyOutcome | None,
        rules_ver: str | None,
        snapshot: Path | None,
    ) -> None:
        with session_scope(self.sessions) as s:
            job = s.get(ScanJob, view.id)
            assert job is not None
            for r in results:
                s.add(
                    ScannerRun(
                        job_id=view.id,
                        scanner=r.scanner,
                        version=r.tool_version,
                        rule_pack_version=rules_ver if r.scanner == "semgrep" else None,
                        status=r.status.value,
                        duration_ms=r.duration_ms,
                        reason=r.reason,
                        stderr_tail=r.stderr_tail[-2000:] or None,
                        db_snapshot=r.db_snapshot
                        or (snapshot.name if snapshot and r.scanner == "osv" else None),
                    )
                )
            if outcome is None:
                return
            for d in outcome.decisions:
                f = d.finding
                s.add(
                    FindingRow(
                        job_id=view.id,
                        fingerprint=f.fingerprint,
                        source=f.source,
                        category=f.category.value,
                        rule_id=f.rule_id,
                        severity=f.severity.value,
                        confidence=f.confidence.value,
                        path=f.path,
                        start_line=f.start_line,
                        end_line=f.end_line,
                        commit_sha=f.commit,
                        message=f.message,
                        evidence=list(f.evidence),
                        extra={
                            "cwe": list(f.cwe),
                            "vuln_ids": list(f.vuln_ids),
                            "rule_version": f.rule_version,
                            "scanner_version": f.scanner_version,
                            **f.extra,
                        },
                        outcome=d.outcome.value,
                        waiver=d.waiver.model_dump(mode="json") if d.waiver else None,
                    )
                )

    def _publish(
        self,
        view: JobView,
        state: RunState,
        results: list[ScanResult],
        outcome: PolicyOutcome,
        rules_ver: str | None,
    ) -> None:
        assert state.check_run_id is not None
        gh, inst, repo = self.github, view.installation_id, view.repo_name
        output = render_check(outcome, results, rules_version=rules_ver)
        publish_result(gh, inst, repo, state.check_run_id, output, outcome.conclusion)

        if view.pr_number is None:
            return
        try:  # the check is the primary result; a comment problem must not undo it
            with session_scope(self.sessions) as s:
                known = s.get(PrComment, (view.repo_id, view.pr_number))
                known_id = known.comment_id if known else None
            url = f"{self.settings.github_clone_url}/{repo}/runs/{state.check_run_id}"
            body = render_comment(outcome, results, check_url=url)
            comment_id = upsert_summary_comment(gh, inst, repo, view.pr_number, body, known_id)
            with session_scope(self.sessions) as s:
                s.merge(
                    PrComment(repo_id=view.repo_id, pr_number=view.pr_number, comment_id=comment_id)
                )
        except GitHubError as exc:
            log.warning("could not update the pull request comment: %s", exc)

    # ---- check run bookkeeping ----------------------------------------------------------------

    def _ensure_check(self, view: JobView, state: RunState) -> None:
        if state.check_run_id is not None:
            return
        state.check_run_id = self.github.create_check_run(
            view.installation_id,
            view.repo_name,
            name=CHECK_NAME,
            head_sha=view.head_sha,
            external_id=str(view.id),
            title="newsoc is scanning this commit",
            summary=f"Scanning `{view.head_sha[:10]}`. This check updates when the scan finishes.",
        )
        with session_scope(self.sessions) as s:
            job = s.get(ScanJob, view.id)
            assert job is not None
            job.check_run_id = state.check_run_id

    def _note(self, view: JobView, state: RunState, text: str) -> None:
        """Update a check that stays in progress (a retry is coming)."""
        if state.check_run_id is None:
            return
        try:
            self.github.update_check_run(
                view.installation_id,
                view.repo_name,
                state.check_run_id,
                title="newsoc is retrying",
                summary=text,
            )
        except GitHubError as exc:
            log.warning("could not update the check run: %s", exc)

    def _close_check(
        self, view: JobView, state: RunState, conclusion: str, title: str, summary: str
    ) -> None:
        if state.check_run_id is None:
            return
        try:
            self.github.update_check_run(
                view.installation_id,
                view.repo_name,
                state.check_run_id,
                title=title,
                summary=summary,
                conclusion=conclusion,
            )
        except GitHubError:
            log.exception(
                "could not close check run %s; it may stay in progress", state.check_run_id
            )

    def _fail(self, view: JobView, state: RunState, message: str) -> JobOutcome:
        conclusion = fallback_conclusion(state.mode)
        self._close_check(
            view,
            state,
            conclusion.value,
            "newsoc could not complete this check",
            f"{message}\n\nThis is a problem on newsoc's side or with the repository's size or "
            "access, not necessarily in your code. Re-run the check to try again.",
        )
        log.warning("job %s failed: %s", view.id, message)
        return JobOutcome(JobStatus.FAILED, conclusion=conclusion.value, error=message)

    # ---- database helpers ---------------------------------------------------------------------

    def _load(self, job_id: int) -> JobView:
        with session_scope(self.sessions) as s:
            job = s.get(ScanJob, job_id)
            assert job is not None
            repo = s.get(Repository, job.repo_id)
            assert repo is not None
            return JobView(
                id=job.id,
                repo_id=repo.id,
                repo_name=repo.full_name,
                default_branch=repo.default_branch,
                installation_id=repo.installation_id,
                trigger=Trigger(job.trigger),
                pr_number=job.pr_number,
                head_sha=job.head_sha,
                base_sha=job.base_sha,
                base_ref=job.base_ref,
                is_fork=job.is_fork,
                check_run_id=job.check_run_id,
                attempt=job.attempt,
            )

    def _store_pull_request(self, view: JobView) -> None:
        with session_scope(self.sessions) as s:
            job = s.get(ScanJob, view.id)
            assert job is not None
            job.pr_number, job.base_sha = view.pr_number, view.base_sha
            job.base_ref, job.is_fork = view.base_ref, view.is_fork

    def _store_mode(self, job_id: int, mode: Mode) -> None:
        with session_scope(self.sessions) as s:
            job = s.get(ScanJob, job_id)
            assert job is not None
            job.mode = mode.value

    @staticmethod
    def _out_dir(workdir: Path, name: str) -> Path:
        path = workdir / f"out-{name}"
        path.mkdir()
        path.chmod(0o777)  # the container user writes scanner reports here
        return path

    def close_orphan_check(self, job_id: int) -> None:
        """For a job that failed because its workers kept dying: close its check run."""
        view = self._load(job_id)
        with session_scope(self.sessions) as s:
            job = s.get(ScanJob, job_id)
            mode = Mode(job.mode) if job is not None and job.mode else None
        state = RunState(mode=mode, check_run_id=view.check_run_id)
        self._fail(view, state, "The scan did not complete because the worker kept failing.")


def _permanent(exc: Exception) -> bool:
    """Errors that retrying cannot fix: access revoked, repository gone, bad input."""
    return isinstance(exc, GitHubError) and exc.status in PERMANENT_HTTP


def _osv_warning(snapshot: Path) -> str | None:
    try:
        return osvdb.check(snapshot).warning
    except osvdb.StaleDatabaseError:
        return None  # the scanner already reported SCA as Not assessed
