"""Settings, read from NEWSOC_* environment variables.

Secrets (the GitHub App private key, the webhook secret and the fingerprint salt) are never in
the repository. They come from either

* an environment variable (``NEWSOC_GITHUB_PRIVATE_KEY`` and so on), which is what a container
  platform provides; the value is held as a ``SecretStr`` so it cannot leak through ``repr``; or
* a file, by default under ``~/.config/newsoc/<env>/`` as written by ``newsoc create-app``.

A value in the environment wins over a file.
"""

from __future__ import annotations

import base64
import binascii
import os
from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

PACKAGE_ROOT = Path(__file__).resolve().parents[2]
BUNDLED_RULES = PACKAGE_ROOT / "rules" / "semgrep"
DEV_SALT = b"newsoc-dev-salt-change-me"


def _config_dir(env: str = "dev") -> Path:
    return Path.home() / ".config" / "newsoc" / env


class SecretMissing(RuntimeError):
    """A required secret is not configured."""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NEWSOC_", extra="ignore")

    env: str = "dev"
    database_url: str = "postgresql+psycopg://newsoc:newsoc@127.0.0.1:55432/newsoc"

    github_api_url: str = "https://api.github.com"
    github_clone_url: str = "https://github.com"  # overridable so tests can clone from local repos
    github_app_id: int | None = None
    github_private_key: SecretStr | None = None  # PEM text, or the PEM base64-encoded
    github_webhook_secret: SecretStr | None = None
    fingerprint_salt: SecretStr | None = None
    github_private_key_path: Path | None = None
    github_webhook_secret_path: Path | None = None
    fingerprint_salt_path: Path | None = None

    scanner_image: str = "newsoc/scanners:dev"
    # When set, the worker builds the scanner image from this Dockerfile if it is not already on
    # the Docker host, and tags it with a hash of the file (so changing the file rebuilds it).
    scanner_dockerfile: Path | None = None
    bundled_rules_dir: Path = BUNDLED_RULES
    # Where scanner containers read the rules from. Scanner containers are started by the Docker
    # host, so in a containerised worker this must be a directory shared at the SAME path.
    rules_dir: Path = BUNDLED_RULES
    osv_db_root: Path = Path.home() / ".local" / "share" / "newsoc" / "osvdb"
    work_root: Path = Path.home() / ".local" / "share" / "newsoc" / "work"
    osv_refresh_hours: float = Field(default=6.0, description="0 disables the automatic refresh")

    max_concurrent_scanners: int = 2
    job_timeout_s: int = Field(default=900, description="Whole-job limit; the watchdog uses it")
    lease_s: int = Field(
        default=120, description="How long a worker owns a job without a heartbeat"
    )
    max_attempts: int = 3

    def secret_dir(self) -> Path:
        return _config_dir(self.env)

    def _secret(self, value: SecretStr | None, path: Path | None, name: str) -> bytes | None:
        """The secret from the environment, else from its file, else None."""
        if value is not None and value.get_secret_value().strip():
            return value.get_secret_value().strip().encode()
        target = path or self.secret_dir() / name
        return target.read_bytes().strip() if target.is_file() else None

    def _require(
        self, value: SecretStr | None, path: Path | None, name: str, env_var: str
    ) -> bytes:
        secret = self._secret(value, path, name)
        if secret is None:
            raise SecretMissing(
                f"{name} is not configured: set {env_var} or create "
                f"{path or self.secret_dir() / name} (`newsoc create-app` writes it)"
            )
        return secret

    def webhook_secret(self) -> bytes:
        return self._require(
            self.github_webhook_secret,
            self.github_webhook_secret_path,
            "webhook_secret",
            "NEWSOC_GITHUB_WEBHOOK_SECRET",
        )

    def private_key(self) -> str:
        raw = self._require(
            self.github_private_key,
            self.github_private_key_path,
            "app.pem",
            "NEWSOC_GITHUB_PRIVATE_KEY",
        )
        return _pem(raw)

    def salt(self) -> bytes:
        """Keys the fingerprint of every secret finding. Only ``dev`` may use a built-in value:
        elsewhere a missing salt is an error, not a silent weakening."""
        found = self._secret(self.fingerprint_salt, self.fingerprint_salt_path, "fingerprint_salt")
        if found is not None:
            return found
        if self.env == "dev":
            return DEV_SALT
        raise SecretMissing(
            f"fingerprint_salt is not configured for env {self.env!r}: set NEWSOC_FINGERPRINT_SALT"
        )


def _pem(raw: bytes) -> str:
    """Accept PEM text (with real or escaped newlines) or the same PEM base64-encoded, because
    multi-line values are awkward in many environment-variable editors."""
    text = raw.decode()
    if "-----BEGIN" in text:
        return text.replace("\\n", "\n")
    try:
        decoded = base64.b64decode(text, validate=True).decode()
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise SecretMissing("the private key is neither PEM text nor base64 of a PEM") from exc
    if "-----BEGIN" not in decoded:
        raise SecretMissing("the private key is neither PEM text nor base64 of a PEM")
    return decoded


@lru_cache
def get_settings() -> Settings:
    """Settings from NEWSOC_* variables, plus ``~/.config/newsoc/<env>/app.env`` (written by
    ``newsoc create-app``) for the GitHub App id. Real environment variables win."""
    env = os.environ.get("NEWSOC_ENV", "dev")
    return Settings(_env_file=_config_dir(env) / "app.env")
