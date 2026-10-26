"""Apply parsed webhook actions to the database: keep installations and repositories current,
enqueue scans, and supersede work for closed pull requests."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from newsoc_code.db.models import Installation, Repository, utcnow
from newsoc_code.github.events import (
    CancelPullRequest,
    InstallationChange,
    Parsed,
    RepoRef,
    RepositoriesChange,
    ScanRequest,
)
from newsoc_code.queue import jobs


@dataclass
class IntakeResult:
    job_ids: list[int] = field(default_factory=list)
    superseded: list[int] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _ensure_installation(
    session: Session, installation_id: int, login: str, account_type: str
) -> Installation:
    """Create the installation if we missed its ``installation`` event (webhook downtime)."""
    session.execute(
        pg_insert(Installation)
        .values(id=installation_id, account_login=login, account_type=account_type)
        .on_conflict_do_nothing()
    )
    inst = session.get(Installation, installation_id)
    assert inst is not None
    return inst


def _upsert_repo(
    session: Session,
    installation_id: int,
    repo_id: int,
    full_name: str,
    default_branch: str | None = None,
) -> None:
    values = {"id": repo_id, "installation_id": installation_id, "full_name": full_name}
    update = {"installation_id": installation_id, "full_name": full_name}
    if default_branch:
        values["default_branch"] = default_branch
        update["default_branch"] = default_branch
    # A repository renamed or transferred keeps its id; a stale row holding the new name goes.
    session.execute(
        delete(Repository).where(Repository.full_name == full_name, Repository.id != repo_id)
    )
    session.execute(
        pg_insert(Repository)
        .values(**values)
        .on_conflict_do_update(index_elements=[Repository.id], set_=update)
    )


def _usable_repo(session: Session, ref: RepoRef) -> tuple[Repository | None, str]:
    inst = _ensure_installation(session, ref.installation_id, ref.owner, ref.owner_type)
    _upsert_repo(session, ref.installation_id, ref.id, ref.full_name, ref.default_branch)
    repo = session.get(Repository, ref.id, populate_existing=True)
    assert repo is not None
    if inst.suspended_at is not None:
        return None, f"installation {inst.id} is suspended"
    if not repo.enabled:
        return None, f"{repo.full_name} is disabled"
    return repo, ""


def apply_actions(session: Session, parsed: Parsed, now: datetime | None = None) -> IntakeResult:
    now = now or utcnow()
    result = IntakeResult()
    if parsed.note:
        result.notes.append(parsed.note)
    for action in parsed.actions:
        if isinstance(action, ScanRequest):
            repo, why = _usable_repo(session, action.repo)
            if repo is None:
                result.notes.append(why)
                continue
            job = jobs.enqueue(
                session,
                repo_id=repo.id,
                trigger=action.trigger,
                head_sha=action.head_sha,
                pr_number=action.pr_number,
                base_sha=action.base_sha,
                base_ref=action.base_ref,
                is_fork=action.is_fork,
                now=now,
            )
            if job is None:
                result.notes.append("already queued for this commit")
            else:
                result.job_ids.append(job.id)
        elif isinstance(action, CancelPullRequest):
            stopped = jobs.supersede(
                session, action.repo.id, action.pr_number, keep_head_sha="", now=now
            )
            result.superseded += [j.id for j in stopped]
        elif isinstance(action, InstallationChange):
            _apply_installation(session, action, now)
        elif isinstance(action, RepositoriesChange):
            _ensure_installation(session, action.installation_id, action.account_login, "User")
            for repo_id, full_name in action.added:
                _upsert_repo(session, action.installation_id, repo_id, full_name)
            for repo_id, _name in action.removed:
                session.execute(delete(Repository).where(Repository.id == repo_id))
    return result


def _apply_installation(session: Session, change: InstallationChange, now: datetime) -> None:
    if change.action == "deleted":
        session.execute(delete(Installation).where(Installation.id == change.installation_id))
        return
    inst = _ensure_installation(
        session, change.installation_id, change.account_login, change.account_type
    )
    if change.action == "suspend":
        inst.suspended_at = now
    elif change.action == "unsuspend":
        inst.suspended_at = None
    for repo_id, full_name in change.repos:
        _upsert_repo(session, change.installation_id, repo_id, full_name)


def active_repo_ids(session: Session, installation_id: int) -> list[int]:
    return list(
        session.scalars(select(Repository.id).where(Repository.installation_id == installation_id))
    )
