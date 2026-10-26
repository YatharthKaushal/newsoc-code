"""Wires the real queue, worker and job processor to a fake GitHub API and a local git remote.

Shared by the fake-scanner pipeline tests and the Docker-backed end-to-end test.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

from fake_github import FakeGitHub
from fake_scanners import FakeRunner, MarkerSast
from gitremote import Remote
from sqlalchemy import select, update
from sqlalchemy.orm import Session, sessionmaker

from newsoc_code.config import Settings
from newsoc_code.db.models import (
    FindingRow,
    Installation,
    Repository,
    ScanJob,
    Trigger,
)
from newsoc_code.github.fetch import Workspace
from newsoc_code.pipeline import JobProcessor
from newsoc_code.queue import jobs
from newsoc_code.queue.worker import Worker

REPO_ID = 1001
ENFORCE = "version: 1\nmode: enforce\n"
OBSERVE = "version: 1\nmode: observe\n"
VULN = "const x = run(VULN(input));\n"


@dataclass
class Harness:
    db: sessionmaker[Session]
    remote: Remote
    gh: FakeGitHub
    sast: MarkerSast
    settings: Settings
    worker: Worker
    processor: JobProcessor
    runners: list[FakeRunner]
    work_root: Path
    runner_class: Callable[[threading.Event], FakeRunner]
    extra_adapters: list[Any]

    # ---- scenario building -------------------------------------------------------------------

    def base_commit(self, files: dict[str, str | None] | None = None) -> str:
        return self.remote.commit({"app.js": "const a = 1;\n", **(files or {})})

    def branch_commit(self, files: dict[str, str | None], branch: str = "feature") -> str:
        sha = self.remote.commit(files, branch=branch)
        self.remote.checkout("main")
        return sha

    def queue_pr(self, number: int, head: str, base: str, **kw: Any) -> int:
        self.gh.add_pull(number, head, base, **kw)
        return self.enqueue(
            trigger=Trigger.PULL_REQUEST,
            pr_number=number,
            head_sha=head,
            base_sha=base,
            base_ref="main",
        )

    def enqueue(self, **kw: Any) -> int:
        with self.db() as s:
            job = jobs.enqueue(s, repo_id=REPO_ID, **kw)
            s.commit()
            assert job is not None
            return job.id

    # ---- running and inspecting --------------------------------------------------------------

    def run(self) -> None:
        assert self.worker.run_once(), "there was no runnable job"

    def job(self, job_id: int) -> ScanJob:
        with self.db() as s:
            job = s.get(ScanJob, job_id)
            assert job is not None
            return job

    def findings(self, job_id: int) -> list[FindingRow]:
        with self.db() as s:
            return list(s.scalars(select(FindingRow).where(FindingRow.job_id == job_id)))

    def make_due(self, job_id: int) -> None:
        with self.db() as s:
            s.execute(
                update(ScanJob)
                .where(ScanJob.id == job_id)
                .values(run_after=datetime.now(UTC) - timedelta(seconds=1))
            )
            s.commit()

    def leftovers(self) -> list[Path]:
        return list(self.work_root.glob("*")) if self.work_root.exists() else []


def build_harness(
    tmp_path: Path,
    db: sessionmaker[Session],
    private_key: str,
    *,
    settings_overrides: dict[str, Any] | None = None,
    adapters: Callable[[], list[Any]] | None = None,
    real_runner: Callable[[threading.Event], Any] | None = None,
) -> Harness:
    """Wire the real queue, worker and processor to a fake GitHub and a local git remote.

    By default scanners are fakes. Pass ``adapters`` and ``real_runner`` to run real ones.
    """
    remote = Remote(tmp_path / "remote")
    gh = FakeGitHub(remote, private_key)
    sast = MarkerSast()
    runners: list[FakeRunner] = []
    extra: list[Any] = []
    work_root = tmp_path / "work"
    settings = Settings(
        **{
            "work_root": work_root,
            "rules_dir": tmp_path / "no-rules",
            "osv_db_root": tmp_path / "no-osv",
            "max_attempts": 3,
            "lease_s": 60,
            "job_timeout_s": 600,
            **(settings_overrides or {}),
        }
    )
    holder: dict[str, Callable[[threading.Event], Any]] = {"make": real_runner or FakeRunner}

    def runner_factory(cancel: threading.Event) -> Any:
        runner = holder["make"](cancel)
        runners.append(runner)
        return runner

    processor = JobProcessor(
        settings=settings,
        session_factory=db,
        github=gh.client,
        runner_factory=runner_factory,
        workspace_factory=lambda root, repo, token: Workspace(
            root, remote.url, token, allow_file_protocol=True
        ),
        adapters_factory=adapters or (lambda: [sast, *extra]),
        today=lambda: date(2026, 10, 26),
    )
    worker = Worker(session_factory=db, processor=processor, settings=settings, heartbeat_s=0.05)
    with db() as s:
        s.add(Installation(id=99, account_login="acme"))
        s.add(Repository(id=REPO_ID, installation_id=99, full_name="acme/app"))
        s.commit()

    harness = Harness(
        db, remote, gh, sast, settings, worker, processor, runners, work_root, FakeRunner, extra
    )

    def use_runner(factory: Callable[[threading.Event], FakeRunner]) -> None:
        holder["make"] = factory

    harness.use_runner = use_runner  # type: ignore[attr-defined]
    return harness
