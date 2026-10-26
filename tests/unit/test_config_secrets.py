from __future__ import annotations

import base64
from pathlib import Path

import pytest

from newsoc_code.config import DEV_SALT, SecretMissing, Settings

# Built from pieces so the repository never contains a key-shaped literal (secret scanners and
# GitHub push protection would flag it, even though this one is fake).
_LABEL = "PRIVATE" + " KEY"
PEM = f"-----BEGIN {_LABEL}-----\nZmFrZSBrZXkgYm9keSBmb3IgdGVzdHM=\n-----END {_LABEL}-----\n"


def settings(tmp_path: Path, **kw: object) -> Settings:
    """Settings that cannot see the developer's real ~/.config or environment."""
    base = {"env": "prod", "github_private_key_path": None}
    return Settings(_env_file=None, **{**base, **kw})  # type: ignore[arg-type]


@pytest.fixture(autouse=True)
def isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    for name in (
        "NEWSOC_GITHUB_PRIVATE_KEY",
        "NEWSOC_GITHUB_WEBHOOK_SECRET",
        "NEWSOC_FINGERPRINT_SALT",
    ):
        monkeypatch.delenv(name, raising=False)


# ---- where a secret comes from ---------------------------------------------------------------


def test_a_secret_can_come_from_the_environment(tmp_path: Path) -> None:
    s = settings(tmp_path, github_webhook_secret="from-env")
    assert s.webhook_secret() == b"from-env"


def test_a_secret_can_come_from_a_file(tmp_path: Path) -> None:
    f = tmp_path / "secret"
    f.write_text("from-file\n")
    assert settings(tmp_path, github_webhook_secret_path=f).webhook_secret() == b"from-file"


def test_the_environment_wins_over_a_file(tmp_path: Path) -> None:
    f = tmp_path / "secret"
    f.write_text("from-file")
    s = settings(tmp_path, github_webhook_secret="from-env", github_webhook_secret_path=f)
    assert s.webhook_secret() == b"from-env"


def test_a_blank_environment_value_falls_back_to_the_file(tmp_path: Path) -> None:
    f = tmp_path / "secret"
    f.write_text("from-file")
    s = settings(tmp_path, github_webhook_secret="   ", github_webhook_secret_path=f)
    assert s.webhook_secret() == b"from-file"


def test_the_default_location_is_the_per_environment_config_dir(tmp_path: Path) -> None:
    directory = tmp_path / "home" / ".config" / "newsoc" / "prod"
    directory.mkdir(parents=True)
    (directory / "webhook_secret").write_text("in-config-dir")
    assert settings(tmp_path).webhook_secret() == b"in-config-dir"


def test_a_missing_secret_names_the_variable_to_set(tmp_path: Path) -> None:
    with pytest.raises(SecretMissing, match="NEWSOC_GITHUB_WEBHOOK_SECRET"):
        settings(tmp_path).webhook_secret()
    with pytest.raises(SecretMissing, match="NEWSOC_GITHUB_PRIVATE_KEY"):
        settings(tmp_path).private_key()


def test_secrets_do_not_leak_through_repr(tmp_path: Path) -> None:
    s = settings(tmp_path, github_webhook_secret="hunter2-secret", fingerprint_salt="salty-salt")
    assert "hunter2-secret" not in repr(s) and "salty-salt" not in repr(s)
    assert "hunter2-secret" not in str(s.model_dump())


# ---- the private key's format ----------------------------------------------------------------


def test_the_private_key_accepts_pem_text(tmp_path: Path) -> None:
    assert settings(tmp_path, github_private_key=PEM).private_key() == PEM.strip()


def test_the_private_key_accepts_escaped_newlines(tmp_path: Path) -> None:
    """Some environment-variable editors turn a multi-line value into one line with \\n."""
    one_line = PEM.strip().replace("\n", "\\n")
    assert settings(tmp_path, github_private_key=one_line).private_key() == PEM.strip()


def test_the_private_key_accepts_base64(tmp_path: Path) -> None:
    encoded = base64.b64encode(PEM.encode()).decode()
    assert settings(tmp_path, github_private_key=encoded).private_key() == PEM


@pytest.mark.parametrize("junk", ["not a key", base64.b64encode(b"not a key").decode(), "%%%%"])
def test_a_private_key_that_is_neither_pem_nor_base64_pem_is_rejected(
    tmp_path: Path, junk: str
) -> None:
    with pytest.raises(SecretMissing, match="neither PEM"):
        settings(tmp_path, github_private_key=junk).private_key()


# ---- the fingerprint salt --------------------------------------------------------------------


def test_only_dev_may_fall_back_to_a_built_in_salt(tmp_path: Path) -> None:
    assert settings(tmp_path, env="dev").salt() == DEV_SALT
    with pytest.raises(SecretMissing, match="NEWSOC_FINGERPRINT_SALT"):
        settings(tmp_path, env="prod").salt()


def test_a_configured_salt_is_used_in_every_environment(tmp_path: Path) -> None:
    assert settings(tmp_path, env="prod", fingerprint_salt="real-salt").salt() == b"real-salt"
    assert settings(tmp_path, env="dev", fingerprint_salt="real-salt").salt() == b"real-salt"
