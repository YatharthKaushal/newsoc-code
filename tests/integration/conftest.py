from __future__ import annotations

from pathlib import Path

import pytest
from fake_github import make_private_key
from pipeline_harness import Harness, build_harness
from sqlalchemy.orm import Session, sessionmaker


@pytest.fixture(scope="module")
def private_key() -> str:
    return make_private_key()


@pytest.fixture
def h(tmp_path: Path, db: sessionmaker[Session], private_key: str) -> Harness:
    """The pipeline wired to a fake GitHub, a local git remote and fake scanners."""
    return build_harness(tmp_path, db, private_key)
