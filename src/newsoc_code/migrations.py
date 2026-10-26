"""Apply database migrations from inside the application (``newsoc serve --migrate``)."""

from __future__ import annotations

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine

from newsoc_code.config import PACKAGE_ROOT


def upgrade_to_head(engine: Engine) -> None:
    """Bring the schema up to date. Safe to run repeatedly and from several processes: alembic
    takes a lock on its version table, and an up-to-date schema is a no-op."""
    cfg = Config(str(PACKAGE_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(PACKAGE_ROOT / "alembic"))
    with engine.begin() as connection:
        cfg.attributes["connection"] = connection
        command.upgrade(cfg, "head")
