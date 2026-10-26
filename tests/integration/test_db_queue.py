"""The Postgres job queue, against a real database built by the real migrations."""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, sessionmaker

from newsoc_code.db.models import Base, Installation, JobStatus, Repository, ScanJob, Trigger
from newsoc_code.queue import jobs

pytestmark = pytest.mark.pg

T0 = datetime(2026, 10, 26, 12, 0, tzinfo=UTC)
LEASE = 120


@pytest.fixture
def repo_id(db: sessionmaker[Session]) -> int:
    with db() as s:
        s.add(Installation(id=1, account_login="acme"))
        s.add(Repository(id=10, installation_id=1, full_name="acme/app"))
        s.add(Repository(id=11, installation_id=1, full_name="acme/other"))
        s.commit()
    return 10


def pr(s: Session, repo: int, number: int, sha: str, at: datetime = T0) -> ScanJob | None:
    job = jobs.enqueue(
        s, repo_id=repo, trigger=Trigger.PULL_REQUEST, pr_number=number, head_sha=sha, now=at
    )
    s.commit()
    return job


def test_migrations_match_the_models(pg_engine: Engine) -> None:
    """If a model changes without a migration, this fails (the diff must be empty)."""
    with pg_engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == []


def test_enqueue_creates_a_queued_job(db: sessionmaker[Session], repo_id: int) -> None:
    with db() as s:
        job = pr(s, repo_id, 7, "a" * 40)
        assert job is not None
        assert (job.status, job.attempt, job.pr_number) == ("queued", 0, 7)


def test_same_revision_is_enqueued_once(db: sessionmaker[Session], repo_id: int) -> None:
    with db() as s:
        assert pr(s, repo_id, 7, "a" * 40) is not None
        assert pr(s, repo_id, 7, "a" * 40) is None  # a redelivered webhook
        assert len(s.scalars(select(ScanJob)).all()) == 1


def test_push_jobs_without_a_pr_number_are_also_deduplicated(
    db: sessionmaker[Session], repo_id: int
) -> None:
    """NULL pr_number must not defeat the unique index (NULLS NOT DISTINCT)."""
    with db() as s:
        for expected in (True, False):
            job = jobs.enqueue(s, repo_id=repo_id, trigger=Trigger.PUSH, head_sha="b" * 40, now=T0)
            s.commit()
            assert (job is not None) is expected


def test_a_completed_revision_can_be_queued_again(db: sessionmaker[Session], repo_id: int) -> None:
    """A re-run of the same commit is allowed once the previous job is no longer active."""
    with db() as s:
        pr(s, repo_id, 7, "a" * 40)
        job = jobs.claim_next(s, "w1", LEASE, now=T0)
        assert job is not None
        assert jobs.complete(s, job.id, "w1", status=JobStatus.DONE, conclusion="success", now=T0)
        s.commit()
        assert pr(s, repo_id, 7, "a" * 40) is not None


def test_a_new_push_supersedes_the_old_queued_job(db: sessionmaker[Session], repo_id: int) -> None:
    with db() as s:
        old = pr(s, repo_id, 7, "a" * 40)
        new = pr(s, repo_id, 7, "b" * 40)
        assert old is not None and new is not None
        s.refresh(old)
        assert old.status == "superseded"
        assert new.status == "queued"


def test_supersede_is_scoped_to_one_pull_request(db: sessionmaker[Session], repo_id: int) -> None:
    with db() as s:
        a = pr(s, repo_id, 7, "a" * 40)
        b = pr(s, repo_id, 8, "b" * 40)  # another PR in the same repository
        c = pr(s, 11, 7, "c" * 40)  # the same number in another repository
        pr(s, repo_id, 7, "d" * 40)
        assert a is not None and b is not None and c is not None
        s.refresh(a), s.refresh(b), s.refresh(c)
        assert (a.status, b.status, c.status) == ("superseded", "queued", "queued")


def test_superseding_a_running_job_tells_its_worker_to_stop(
    db: sessionmaker[Session], repo_id: int
) -> None:
    with db() as s:
        pr(s, repo_id, 7, "a" * 40)
        running = jobs.claim_next(s, "w1", LEASE, now=T0)
        s.commit()
        assert running is not None
        assert jobs.heartbeat(s, running.id, "w1", LEASE, now=T0)

        pr(s, repo_id, 7, "b" * 40)  # the author pushed again

        assert not jobs.heartbeat(s, running.id, "w1", LEASE, now=T0)
        assert jobs.is_superseded(s, running.id)
        assert not jobs.complete(s, running.id, "w1", status=JobStatus.DONE, now=T0)
        s.refresh(running)
        assert running.status == "superseded"  # the late completion did not overwrite it


def test_claim_takes_the_oldest_job_first(db: sessionmaker[Session], repo_id: int) -> None:
    with db() as s:
        pr(s, repo_id, 1, "1" * 40, T0)
        pr(s, repo_id, 2, "2" * 40, T0 + timedelta(seconds=5))
        first = jobs.claim_next(s, "w1", LEASE, now=T0 + timedelta(seconds=10))
        second = jobs.claim_next(s, "w1", LEASE, now=T0 + timedelta(seconds=10))
        assert first is not None and second is not None
        assert (first.pr_number, second.pr_number) == (1, 2)
        assert first.status == "running" and first.attempt == 1 and first.locked_by == "w1"
        assert jobs.claim_next(s, "w1", LEASE, now=T0) is None


def test_claim_skips_jobs_that_are_not_due(db: sessionmaker[Session], repo_id: int) -> None:
    with db() as s:
        job = pr(s, repo_id, 1, "1" * 40)
        assert job is not None
        job.run_after = T0 + timedelta(minutes=5)
        s.commit()
        assert jobs.claim_next(s, "w1", LEASE, now=T0) is None
        assert jobs.claim_next(s, "w1", LEASE, now=T0 + timedelta(minutes=6)) is not None


def test_concurrent_workers_never_claim_the_same_job(
    db: sessionmaker[Session], repo_id: int
) -> None:
    total = 12
    with db() as s:
        for n in range(total):
            pr(s, repo_id, n + 1, f"{n:040d}")

    claimed: list[int] = []
    errors: list[BaseException] = []
    lock = threading.Lock()
    barrier = threading.Barrier(6)

    def work(name: str) -> None:
        try:
            barrier.wait()
            while True:
                with db() as s:
                    job = jobs.claim_next(s, name, LEASE, now=T0)
                    s.commit()
                    if job is None:
                        return
                    with lock:
                        claimed.append(job.id)
        except BaseException as exc:  # pragma: no cover (reported below)
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(f"w{i}",)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert not errors
    assert len(claimed) == total
    assert len(set(claimed)) == total  # every job exactly once


def test_heartbeat_extends_the_lease_only_for_the_owner(
    db: sessionmaker[Session], repo_id: int
) -> None:
    with db() as s:
        pr(s, repo_id, 1, "1" * 40)
        job = jobs.claim_next(s, "w1", LEASE, now=T0)
        assert job is not None
        assert not jobs.heartbeat(s, job.id, "intruder", LEASE, now=T0)
        assert jobs.heartbeat(s, job.id, "w1", LEASE, now=T0 + timedelta(seconds=100))
        s.refresh(job)
        assert job.locked_until == T0 + timedelta(seconds=100 + LEASE)


def test_complete_records_the_outcome(db: sessionmaker[Session], repo_id: int) -> None:
    with db() as s:
        pr(s, repo_id, 1, "1" * 40)
        job = jobs.claim_next(s, "w1", LEASE, now=T0)
        assert job is not None
        done = jobs.complete(
            s, job.id, "w1", status=JobStatus.FAILED, conclusion="neutral", error="boom" * 2000
        )
        assert done
        s.refresh(job)
        assert (job.status, job.conclusion, job.locked_until) == ("failed", "neutral", None)
        assert job.error is not None and len(job.error) == 2000
        assert not jobs.complete(s, job.id, "w1", status=JobStatus.DONE)  # already finished


def test_reaper_requeues_a_job_whose_worker_vanished(
    db: sessionmaker[Session], repo_id: int
) -> None:
    with db() as s:
        pr(s, repo_id, 1, "1" * 40)
        job = jobs.claim_next(s, "w1", LEASE, now=T0)
        assert job is not None
        assert jobs.reap_expired(s, max_attempts=3, now=T0 + timedelta(seconds=LEASE - 1)) == (
            jobs.Reaped()
        )  # the lease has not expired yet

        late = T0 + timedelta(seconds=LEASE + 1)
        reaped = jobs.reap_expired(s, max_attempts=3, now=late)
        assert reaped.requeued == [job.id] and reaped.failed == []
        s.refresh(job)
        assert job.status == "queued" and job.locked_by is None
        assert job.run_after == late + timedelta(seconds=jobs.RETRY_BACKOFF_S[0])
        # not claimable until the backoff has passed
        assert jobs.claim_next(s, "w2", LEASE, now=late) is None
        assert jobs.claim_next(s, "w2", LEASE, now=late + timedelta(seconds=20)) is not None


def test_reaper_fails_a_job_that_keeps_losing_its_worker(
    db: sessionmaker[Session], repo_id: int
) -> None:
    with db() as s:
        pr(s, repo_id, 1, "1" * 40)
        now = T0
        for attempt in (1, 2, 3):
            job = jobs.claim_next(s, "w1", LEASE, now=now)
            assert job is not None and job.attempt == attempt
            now += timedelta(seconds=LEASE + 1)
            reaped = jobs.reap_expired(s, max_attempts=3, now=now)
            now += timedelta(minutes=10)  # past any backoff
        assert [j.id for j in reaped.failed] == [job.id]
        s.refresh(job)
        assert job.status == "failed" and "gave up" in (job.error or "")


def test_reaper_enforces_a_hard_limit_even_while_the_lease_is_renewed(
    db: sessionmaker[Session], repo_id: int
) -> None:
    """A hung job whose heartbeat keeps running must still be recovered."""
    with db() as s:
        pr(s, repo_id, 1, "1" * 40)
        job = jobs.claim_next(s, "w1", LEASE, now=T0)
        assert job is not None
        later = T0 + timedelta(seconds=1000)
        assert jobs.heartbeat(s, job.id, "w1", LEASE, now=later)  # lease is fresh
        assert jobs.reap_expired(s, max_attempts=3, now=later) == jobs.Reaped()
        reaped = jobs.reap_expired(s, max_attempts=3, hard_limit_s=900, now=later)
        assert reaped.requeued == [job.id]
