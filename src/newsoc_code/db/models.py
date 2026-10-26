"""Database tables (plan.md section 3 data model).

Secrets are never stored. Findings keep redacted evidence only (a few masked source lines).
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, ClassVar

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

JsonType = JSON().with_variant(JSONB(), "postgresql")


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    type_annotation_map: ClassVar[dict[Any, Any]] = {
        dict[str, Any]: JsonType,
        list[Any]: JsonType,
        datetime: DateTime(timezone=True),
    }


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    SUPERSEDED = "superseded"  # a newer push replaced it
    CANCELLED = "cancelled"

    @property
    def active(self) -> bool:
        return self in (JobStatus.QUEUED, JobStatus.RUNNING)


class Trigger(StrEnum):
    PULL_REQUEST = "pull_request"
    PUSH = "push"  # default branch: builds the baseline, does not gate
    RERUN = "rerun"
    MERGE_GROUP = "merge_group"


class Installation(Base):
    __tablename__ = "installations"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)  # GitHub installation id
    account_login: Mapped[str] = mapped_column(String(255))
    account_type: Mapped[str] = mapped_column(String(32), default="Organization")
    suspended_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(default=utcnow)

    repositories: Mapped[list[Repository]] = relationship(back_populates="installation")


class Repository(Base):
    __tablename__ = "repositories"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)  # GitHub repository id
    installation_id: Mapped[int] = mapped_column(ForeignKey("installations.id", ondelete="CASCADE"))
    full_name: Mapped[str] = mapped_column(String(255), unique=True)
    default_branch: Mapped[str] = mapped_column(String(255), default="main")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    installation: Mapped[Installation] = relationship(back_populates="repositories")


class WebhookDelivery(Base):
    """The delivery id is the primary key, which gives idempotency for free."""

    __tablename__ = "webhook_deliveries"

    delivery_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    event: Mapped[str] = mapped_column(String(64))
    action: Mapped[str | None] = mapped_column(String(64))
    received_at: Mapped[datetime] = mapped_column(default=utcnow)
    payload_sha256: Mapped[str] = mapped_column(String(64))
    processed_at: Mapped[datetime | None]


class ScanJob(Base):
    __tablename__ = "scan_jobs"
    __table_args__ = (
        # One active job per revision: a duplicate enqueue is a no-op.
        Index(
            "uq_scan_jobs_active_revision",
            "repo_id",
            "trigger",
            "pr_number",
            "head_sha",
            unique=True,
            postgresql_where=text("status IN ('queued', 'running')"),
            postgresql_nulls_not_distinct=True,
        ),
        Index("ix_scan_jobs_claim", "status", "run_after", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    repo_id: Mapped[int] = mapped_column(ForeignKey("repositories.id", ondelete="CASCADE"))
    trigger: Mapped[str] = mapped_column(String(32))
    pr_number: Mapped[int | None] = mapped_column(Integer)
    head_sha: Mapped[str] = mapped_column(String(64))
    base_sha: Mapped[str | None] = mapped_column(String(64))
    base_ref: Mapped[str | None] = mapped_column(String(255))
    is_fork: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(16), default=JobStatus.QUEUED.value)
    attempt: Mapped[int] = mapped_column(Integer, default=0)
    check_run_id: Mapped[int | None] = mapped_column(BigInteger)
    mode: Mapped[str | None] = mapped_column(
        String(16)
    )  # observe | enforce, once the policy is read
    locked_by: Mapped[str | None] = mapped_column(String(128))
    locked_until: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    run_after: Mapped[datetime] = mapped_column(default=utcnow)
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]
    conclusion: Mapped[str | None] = mapped_column(String(32))
    error: Mapped[str | None] = mapped_column(Text)

    repo: Mapped[Repository] = relationship()
    scanner_runs: Mapped[list[ScannerRun]] = relationship(cascade="all, delete-orphan")
    findings: Mapped[list[FindingRow]] = relationship(cascade="all, delete-orphan")


class ScannerRun(Base):
    __tablename__ = "scanner_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id", ondelete="CASCADE"), index=True)
    scanner: Mapped[str] = mapped_column(String(64))
    version: Mapped[str | None] = mapped_column(String(64))
    rule_pack_version: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32))
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    reason: Mapped[str | None] = mapped_column(Text)
    stderr_tail: Mapped[str | None] = mapped_column(Text)
    db_snapshot: Mapped[str | None] = mapped_column(String(128))


class FindingRow(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    source: Mapped[str] = mapped_column(String(64))
    category: Mapped[str] = mapped_column(String(16))
    rule_id: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[str] = mapped_column(String(16))
    path: Mapped[str] = mapped_column(Text)
    start_line: Mapped[int] = mapped_column(Integer)
    end_line: Mapped[int] = mapped_column(Integer)
    commit_sha: Mapped[str | None] = mapped_column(String(64))
    message: Mapped[str] = mapped_column(Text)
    evidence: Mapped[list[Any]]
    extra: Mapped[dict[str, Any]]
    outcome: Mapped[str] = mapped_column(
        String(16)
    )  # blocked | would_block | warned | waived | baselined
    waiver: Mapped[dict[str, Any] | None]


class BaselineRow(Base):
    """Fingerprints from a scan of a base commit, reused across pull requests."""

    __tablename__ = "baselines"

    repo_id: Mapped[int] = mapped_column(
        ForeignKey("repositories.id", ondelete="CASCADE"), primary_key=True
    )
    commit_sha: Mapped[str] = mapped_column(String(64), primary_key=True)
    scanner_key: Mapped[str] = mapped_column(
        String(64), primary_key=True
    )  # tool + rule pack versions
    fingerprints: Mapped[list[Any]]
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class PrComment(Base):
    __tablename__ = "pr_comments"

    repo_id: Mapped[int] = mapped_column(
        ForeignKey("repositories.id", ondelete="CASCADE"), primary_key=True
    )
    pr_number: Mapped[int] = mapped_column(Integer, primary_key=True)
    comment_id: Mapped[int] = mapped_column(BigInteger)


class AuditLog(Base):
    """Append-only record of decisions that matter: waivers applied, overrides, policy changes."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(64))
    detail: Mapped[dict[str, Any]]
