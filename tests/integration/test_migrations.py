"""``newsoc serve --migrate`` brings an empty database to the current schema, repeatably."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import Engine, inspect, text
from sqlalchemy.engine import make_url

from newsoc_code.db.models import Base
from newsoc_code.db.session import make_engine
from newsoc_code.migrations import upgrade_to_head

pytestmark = pytest.mark.pg


@pytest.fixture
def empty_engine(pg_engine: Engine):
    name = f"newsoc_mig_{uuid.uuid4().hex[:8]}"
    with pg_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    url = make_url(pg_engine.url.render_as_string(hide_password=False)).set(database=name)
    engine = make_engine(url.render_as_string(hide_password=False))
    yield engine
    engine.dispose()
    with pg_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))


def test_an_empty_database_gets_every_table(empty_engine: Engine) -> None:
    upgrade_to_head(empty_engine)
    tables = set(inspect(empty_engine).get_table_names())
    assert {t.name for t in Base.metadata.sorted_tables} <= tables


def test_running_it_again_changes_nothing(empty_engine: Engine) -> None:
    upgrade_to_head(empty_engine)
    upgrade_to_head(empty_engine)  # an already-migrated database is a no-op, not an error
    with empty_engine.connect() as conn:
        assert conn.execute(text("select count(*) from alembic_version")).scalar() == 1
