"""Shared test helpers."""

from __future__ import annotations

import os
import shutil
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from newsoc_code.db.models import Base
from newsoc_code.db.session import make_engine, make_session_factory
from newsoc_code.runner.base import RunOutput
from newsoc_code.runner.docker import DockerRunner
from newsoc_code.scanners.base import ScanContext, TreeInfo

GOLDEN = Path(__file__).parent / "golden"
SALT = b"unit-test-salt"


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip Docker-backed tests when the daemon or the scanner image is not usable."""
    if not any("docker" in item.keywords for item in items):
        return
    if DockerRunner().available():
        return
    skip = pytest.mark.skip(
        reason="Docker daemon or the newsoc/scanners:dev image is not available"
    )
    for item in items:
        if "docker" in item.keywords:
            item.add_marker(skip)


@pytest.fixture
def make_ctx(tmp_path: Path):
    """Build a ScanContext over ``src`` with a fresh output directory."""

    def _make(src: Path, **overrides) -> ScanContext:
        out = tmp_path / "out"
        out.mkdir(exist_ok=True)
        defaults = {
            "src_root": src,
            "out_dir": out,
            "tree": TreeInfo.scan(src),
            "salt": SALT,
            "rules_dir": tmp_path / "rules",
            "rules_version": "testpack1",
            "osv_db_dir": tmp_path / "osvdb",
        }
        return ScanContext(**{**defaults, **overrides})

    return _make


@pytest.fixture
def place_report():
    """Copy a golden report into the context's output directory under the name a scanner uses."""

    def _place(ctx: ScanContext, golden: str, as_name: str) -> Path:
        dest = ctx.out_dir / as_name
        shutil.copy(GOLDEN / golden, dest)
        return dest

    return _place


def run_output(
    exit_code: int | None = 0, *, timed_out: bool = False, stderr: str = ""
) -> RunOutput:
    return RunOutput(exit_code=exit_code, timed_out=timed_out, stderr_tail=stderr, duration_ms=5)


# ---- Postgres --------------------------------------------------------------------------------

PG_ADMIN_URL = os.environ.get(
    "NEWSOC_TEST_PG_ADMIN_URL", "postgresql+psycopg://newsoc:newsoc@127.0.0.1:55432/postgres"
)
ROOT = Path(__file__).resolve().parents[1]


def _pg_reachable() -> bool:
    try:
        engine = make_engine(PG_ADMIN_URL, connect_args={"connect_timeout": 2})
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
        return True
    except OperationalError:
        return False


def pytest_runtest_setup(item: pytest.Item) -> None:
    if "pg" in item.keywords and not _pg_reachable():
        pytest.skip("dev Postgres is not reachable (docker compose up -d db)")


@pytest.fixture(scope="session")
def pg_engine() -> Iterator[Engine]:
    """A throwaway database built by running the real alembic migrations."""
    name = f"newsoc_test_{uuid.uuid4().hex[:10]}"
    admin = make_engine(PG_ADMIN_URL, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    url = make_url(PG_ADMIN_URL).set(database=name)
    engine = make_engine(url.render_as_string(hide_password=False))
    try:
        cfg = Config(str(ROOT / "alembic.ini"))
        with engine.begin() as conn:
            cfg.attributes["connection"] = conn
            command.upgrade(cfg, "head")
        yield engine
    finally:
        engine.dispose()
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


@pytest.fixture
def db(pg_engine: Engine) -> Iterator[sessionmaker[Session]]:
    """A session factory over an empty database (tables truncated before each test)."""
    tables = ", ".join(f'"{t.name}"' for t in Base.metadata.sorted_tables)
    with pg_engine.begin() as conn:
        conn.execute(text(f"TRUNCATE {tables} RESTART IDENTITY CASCADE"))
    yield make_session_factory(pg_engine)
