"""A job queue on Postgres.

``FOR UPDATE SKIP LOCKED`` lets several workers claim jobs without blocking each other, and a
lease (``locked_until``) lets a crashed worker's job be found and retried. There is no separate
broker to run, back up or lose messages from.

Lifecycle: queued -> running -> done | failed. A newer push to the same pull request moves older
active jobs to ``superseded``; a running worker notices on its next heartbeat and stops.

Every function takes ``now`` so tests control the clock. All writes happen inside the caller's
transaction; the caller commits.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from newsoc_code.db.models import JobStatus, ScanJob, Trigger, utcnow

RETRY_BACKOFF_S = (15, 60, 240)
ACTIVE = (JobStatus.QUEUED.value, JobStatus.RUNNING.value)


@dataclass(frozen=True)
class Reaped:
    """What ``reap_expired`` did. ``failed`` jobs need their check run completed by the caller."""

    requeued: list[int] = field(default_factory=list)
    failed: list[ScanJob] = field(default_factory=list)


def _pr_lock(session: Session, repo_id: int, pr_number: int) -> None:
    """Serialise enqueues for one pull request so two pushes cannot both stay active."""
    session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": f"pr:{repo_id}:{pr_number}"},
    )


def enqueue(
    session: Session,
    *,
    repo_id: int,
    trigger: Trigger,
    head_sha: str,
    pr_number: int | None = None,
    base_sha: str | None = None,
    base_ref: str | None = None,
    is_fork: bool = False,
    now: datetime | None = None,
) -> ScanJob | None:
    """Queue a scan; returns None when the same revision is already queued or running.

    For a pull request, older active jobs for other commits are superseded first.
    """
    now = now or utcnow()
    if pr_number is not None:
        _pr_lock(session, repo_id, pr_number)
        supersede(session, repo_id, pr_number, keep_head_sha=head_sha, now=now)

    stmt = (
        pg_insert(ScanJob)
        .values(
            repo_id=repo_id,
            trigger=trigger.value,
            pr_number=pr_number,
            head_sha=head_sha,
            base_sha=base_sha,
            base_ref=base_ref,
            is_fork=is_fork,
            status=JobStatus.QUEUED.value,
            attempt=0,
            created_at=now,
            run_after=now,
        )
        .on_conflict_do_nothing()  # the partial unique index: same active revision
        .returning(ScanJob.id)
    )
    job_id = session.execute(stmt).scalar_one_or_none()
    return session.get(ScanJob, job_id) if job_id is not None else None


def supersede(
    session: Session,
    repo_id: int,
    pr_number: int,
    *,
    keep_head_sha: str,
    now: datetime | None = None,
) -> list[ScanJob]:
    """Mark active jobs for other commits of this pull request as superseded."""
    now = now or utcnow()
    rows = (
        session.execute(
            update(ScanJob)
            .where(
                ScanJob.repo_id == repo_id,
                ScanJob.pr_number == pr_number,
                ScanJob.status.in_(ACTIVE),
                ScanJob.head_sha != keep_head_sha,
            )
            .values(status=JobStatus.SUPERSEDED.value, finished_at=now, locked_until=None)
            .returning(ScanJob)
        )
        .scalars()
        .all()
    )
    return list(rows)


def claim_next(
    session: Session, worker_id: str, lease_s: int, now: datetime | None = None
) -> ScanJob | None:
    """Take the oldest runnable job, or None. Safe to call from many workers at once."""
    now = now or utcnow()
    job = session.execute(
        select(ScanJob)
        .where(ScanJob.status == JobStatus.QUEUED.value, ScanJob.run_after <= now)
        .order_by(ScanJob.created_at, ScanJob.id)
        .limit(1)
        .with_for_update(skip_locked=True)
    ).scalar_one_or_none()
    if job is None:
        return None
    job.status = JobStatus.RUNNING.value
    job.attempt += 1
    job.locked_by = worker_id
    job.locked_until = now + timedelta(seconds=lease_s)
    job.started_at = now
    session.flush()
    return job


def heartbeat(
    session: Session, job_id: int, worker_id: str, lease_s: int, now: datetime | None = None
) -> bool:
    """Extend the lease. False means this worker no longer owns a running job (it was
    superseded or reaped), and the worker must stop."""
    now = now or utcnow()
    result = session.execute(
        update(ScanJob)
        .where(
            ScanJob.id == job_id,
            ScanJob.locked_by == worker_id,
            ScanJob.status == JobStatus.RUNNING.value,
        )
        .values(locked_until=now + timedelta(seconds=lease_s))
    )
    return bool(result.rowcount)  # type: ignore[attr-defined]


def complete(
    session: Session,
    job_id: int,
    worker_id: str,
    *,
    status: JobStatus,
    conclusion: str | None = None,
    error: str | None = None,
    now: datetime | None = None,
) -> bool:
    """Finish a job this worker owns. False if ownership was lost in the meantime."""
    assert not status.active
    now = now or utcnow()
    result = session.execute(
        update(ScanJob)
        .where(
            ScanJob.id == job_id,
            ScanJob.locked_by == worker_id,
            ScanJob.status == JobStatus.RUNNING.value,
        )
        .values(
            status=status.value,
            conclusion=conclusion,
            error=error[:2000] if error else None,
            finished_at=now,
            locked_until=None,
        )
    )
    return bool(result.rowcount)  # type: ignore[attr-defined]


def requeue(
    session: Session,
    job_id: int,
    worker_id: str,
    *,
    delay_s: int,
    error: str | None = None,
    now: datetime | None = None,
) -> bool:
    """Give a job back after a transient failure. False if this worker no longer owns it."""
    now = now or utcnow()
    result = session.execute(
        update(ScanJob)
        .where(
            ScanJob.id == job_id,
            ScanJob.locked_by == worker_id,
            ScanJob.status == JobStatus.RUNNING.value,
        )
        .values(
            status=JobStatus.QUEUED.value,
            locked_by=None,
            locked_until=None,
            run_after=now + timedelta(seconds=delay_s),
            error=error[:2000] if error else None,
        )
    )
    return bool(result.rowcount)  # type: ignore[attr-defined]


def is_superseded(session: Session, job_id: int) -> bool:
    status = session.execute(select(ScanJob.status).where(ScanJob.id == job_id)).scalar_one()
    return status in (JobStatus.SUPERSEDED.value, JobStatus.CANCELLED.value)


def reap_expired(
    session: Session,
    *,
    max_attempts: int,
    hard_limit_s: int | None = None,
    now: datetime | None = None,
) -> Reaped:
    """Recover running jobs whose worker vanished (lease expired) or that ran past the hard limit.

    A job with attempts left goes back to the queue after a backoff; one without fails, and is
    returned so the caller can complete its check run (a check must never stay in progress).
    """
    now = now or utcnow()
    overdue = ScanJob.locked_until < now
    if hard_limit_s is not None:
        overdue = overdue | (ScanJob.started_at < now - timedelta(seconds=hard_limit_s))
    jobs = (
        session.execute(
            select(ScanJob)
            .where(ScanJob.status == JobStatus.RUNNING.value, overdue)
            .with_for_update(skip_locked=True)
        )
        .scalars()
        .all()
    )
    reaped = Reaped()
    for job in jobs:
        job.locked_by = None
        job.locked_until = None
        if job.attempt >= max_attempts:
            job.status = JobStatus.FAILED.value
            job.finished_at = now
            job.error = f"worker lost or timed out; gave up after {job.attempt} attempts"
            reaped.failed.append(job)
        else:
            backoff = RETRY_BACKOFF_S[min(job.attempt, len(RETRY_BACKOFF_S)) - 1]
            job.status = JobStatus.QUEUED.value
            job.run_after = now + timedelta(seconds=backoff)
            reaped.requeued.append(job.id)
    session.flush()
    return reaped
