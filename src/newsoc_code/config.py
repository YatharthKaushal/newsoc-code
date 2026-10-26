"""Settings, read from NEWSOC_* environment variables.

Secrets are never read from the environment directly or from the repository: the private key,
webhook secret and fingerprint salt are files (``*_path`` settings), by default under
``~/.config/newsoc/<env>/`` written by ``scripts/create_app.py``.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PACKAGE_ROOT = Path(__file__).resolve().parents[2]


def _config_dir(env: str = "dev") -> Path:
    return Path.home() / ".config" / "newsoc" / env


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NEWSOC_", extra="ignore")

    env: str = "dev"
    database_url: str = "postgresql+psycopg://newsoc:newsoc@127.0.0.1:55432/newsoc"

    github_api_url: str = "https://api.github.com"
    github_clone_url: str = "https://github.com"  # overridable so tests can clone from local repos
    github_app_id: int | None = None
    github_private_key_path: Path | None = None
    github_webhook_secret_path: Path | None = None
    fingerprint_salt_path: Path | None = None

    scanner_image: str = "newsoc/scanners:dev"
    rules_dir: Path = PACKAGE_ROOT / "rules" / "semgrep"
    osv_db_root: Path = Path.home() / ".local" / "share" / "newsoc" / "osvdb"
    work_root: Path = Path.home() / ".local" / "share" / "newsoc" / "work"

    max_concurrent_scanners: int = 2
    job_timeout_s: int = Field(default=900, description="Whole-job limit; the watchdog uses it")
    lease_s: int = Field(
        default=120, description="How long a worker owns a job without a heartbeat"
    )
    max_attempts: int = 3

    def secret_dir(self) -> Path:
        return _config_dir(self.env)

    def read_secret(self, path: Path | None, name: str) -> bytes:
        target = path or self.secret_dir() / name
        if not target.is_file():
            raise FileNotFoundError(f"{name} not found at {target}; run scripts/create_app.py")
        return target.read_bytes().strip()

    def webhook_secret(self) -> bytes:
        return self.read_secret(self.github_webhook_secret_path, "webhook_secret")

    def private_key(self) -> str:
        return self.read_secret(self.github_private_key_path, "app.pem").decode()

    def salt(self) -> bytes:
        target = self.fingerprint_salt_path or self.secret_dir() / "fingerprint_salt"
        return target.read_bytes().strip() if target.is_file() else b"newsoc-dev-salt-change-me"


@lru_cache
def get_settings() -> Settings:
    """Settings from NEWSOC_* variables, plus ``~/.config/newsoc/<env>/app.env`` (written by
    ``newsoc create-app``) for the GitHub App id. Real environment variables win."""
    env = os.environ.get("NEWSOC_ENV", "dev")
    return Settings(_env_file=_config_dir(env) / "app.env")
