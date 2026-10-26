"""The worker loop: claim a job, keep its lease alive, run it, record the result.

One worker process runs one job at a time (scanners already use several cores). Leases make
crashes safe: if the process dies, the job's lease expires and ``reap`` hands it to the next
attempt, or fails it and closes its check run once attempts run out.
"""

from __future__ import annotations

import logging
import os
import socket
import threading
import time
import uuid

from sqlalchemy.orm import Session, sessionmaker

from newsoc_code.config import Settings
from newsoc_code.db.models import JobStatus
from newsoc_code.db.session import session_scope
from newsoc_code.pipeline import JobControl, JobOutcome, JobProcessor
from newsoc_code.queue import jobs

log = logging.getLogger("newsoc.worker")


class Worker:
    def __init__(
        self,
        *,
        session_factory: sessionmaker[Session],
        processor: JobProcessor,
        settings: Settings,
        worker_id: str | None = None,
        heartbeat_s: float | None = None,
        reap_every_s: float = 30.0,
    ) -> None:
        self.sessions = session_factory
        self.processor = processor
        self.settings = settings
        self.worker_id = worker_id or f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:6]}"
        self.heartbeat_s = (
            heartbeat_s if heartbeat_s is not None else max(settings.lease_s / 4, 1.0)
        )
        self.reap_every_s = reap_every_s
        self._stop = threading.Event()
        self._active: JobControl | None = None

    # ---- one job ----------------------------------------------------------------------------

    def run_once(self) -> bool:
        """Claim and process one job. Returns False when the queue had nothing runnable."""
        with session_scope(self.sessions) as s:
            job = jobs.claim_next(s, self.worker_id, self.settings.lease_s)
            job_id = job.id if job else None
        if job_id is None:
            return False

        control = JobControl()
        self._active = control
        done = threading.Event()
        beat = threading.Thread(
            target=self._heartbeat, args=(job_id, control, done, time.monotonic()), daemon=True
        )
        beat.start()
        try:
            outcome = self.processor.run(job_id, control)
        except BaseException:  # the processor handles its own errors; this is the last resort
            log.exception("job %s: unhandled error", job_id)
            self._close_check_best_effort(job_id)
            outcome = JobOutcome(JobStatus.FAILED, error="unhandled error in the worker")
        finally:
            done.set()
            beat.join(timeout=5)
            self._active = None
        self._finish(job_id, outcome)
        return True

    def _heartbeat(
        self, job_id: int, control: JobControl, done: threading.Event, started: float
    ) -> None:
        """Renew the lease; stop the job if it was superseded or has run too long."""
        while not done.wait(self.heartbeat_s):
            if time.monotonic() - started > self.settings.job_timeout_s:
                control.stop("timeout")
            try:
                with session_scope(self.sessions) as s:
                    alive = jobs.heartbeat(s, job_id, self.worker_id, self.settings.lease_s)
            except Exception:  # a database blip: the lease is still valid for a while
                log.exception("job %s: heartbeat failed", job_id)
                continue
            if not alive:
                log.info("job %s: no longer ours (superseded or reaped); stopping", job_id)
                control.stop("superseded")
                return

    def _finish(self, job_id: int, outcome: JobOutcome) -> None:
        with session_scope(self.sessions) as s:
            if outcome.status is JobStatus.QUEUED:
                owned = jobs.requeue(
                    s,
                    job_id,
                    self.worker_id,
                    delay_s=outcome.retry_delay_s or 60,
                    error=outcome.error,
                )
            else:
                owned = jobs.complete(
                    s,
                    job_id,
                    self.worker_id,
                    status=outcome.status,
                    conclusion=outcome.conclusion,
                    error=outcome.error,
                )
        if not owned:
            log.info("job %s: result discarded, the job is no longer ours", job_id)

    def _close_check_best_effort(self, job_id: int) -> None:
        try:
            self.processor.close_orphan_check(job_id)
        except Exception:
            log.exception("job %s: could not close its check run", job_id)

    # ---- recovery ---------------------------------------------------------------------------

    def reap(self) -> jobs.Reaped:
        """Recover jobs whose worker vanished; close the checks of those that ran out of tries."""
        with session_scope(self.sessions) as s:
            reaped = jobs.reap_expired(
                s,
                max_attempts=self.settings.max_attempts,
                hard_limit_s=self.settings.job_timeout_s * 2,
            )
            failed = [job.id for job in reaped.failed]
        for job_id in failed:
            log.warning("job %s failed after repeated worker loss", job_id)
            self._close_check_best_effort(job_id)
        return reaped

    # ---- the loop ---------------------------------------------------------------------------

    def run_forever(self, poll_s: float = 2.0) -> None:
        last_reap = 0.0
        while not self._stop.is_set():
            if time.monotonic() - last_reap >= self.reap_every_s:
                last_reap = time.monotonic()
                try:
                    self.reap()
                except Exception:
                    log.exception("reaper failed")
            try:
                worked = self.run_once()
            except Exception:  # database unreachable, etc.: back off and keep going
                log.exception("worker loop error")
                worked = False
            if not worked:
                self._stop.wait(poll_s)

    def request_shutdown(self) -> None:
        """Stop after the current job; the job in progress is returned to the queue."""
        self._stop.set()
        if self._active is not None:
            self._active.stop("shutdown")
