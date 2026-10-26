from __future__ import annotations

from pathlib import Path

import pytest
import respx
from typer.testing import CliRunner

from newsoc_code.cli import app
from newsoc_code.config import get_settings
from newsoc_code.github.signature import verify_signature

runner = CliRunner()


@pytest.fixture
def secret_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> bytes:
    secret = tmp_path / "webhook_secret"
    secret.write_text("replay-secret\n")
    monkeypatch.setenv("NEWSOC_GITHUB_WEBHOOK_SECRET_PATH", str(secret))
    get_settings.cache_clear()
    yield b"replay-secret"
    get_settings.cache_clear()


@respx.mock
def test_replay_webhook_signs_the_payload_with_the_local_secret(
    tmp_path: Path, secret_file: bytes
) -> None:
    payload = tmp_path / "pr.json"
    payload.write_text('{"action": "opened"}')
    route = respx.post("http://127.0.0.1:8000/webhooks/github").respond(
        202, json={"status": "queued"}
    )

    result = runner.invoke(
        app, ["replay-webhook", str(payload), "--event", "pull_request", "--delivery", "d-1"]
    )

    assert result.exit_code == 0 and "202" in result.output
    request = route.calls.last.request
    assert request.headers["x-github-event"] == "pull_request"
    assert request.headers["x-github-delivery"] == "d-1"
    assert verify_signature(secret_file, request.content, request.headers["x-hub-signature-256"])


@respx.mock
def test_replay_webhook_exits_nonzero_when_the_server_refuses(
    tmp_path: Path, secret_file: bytes
) -> None:
    payload = tmp_path / "pr.json"
    payload.write_text("{}")
    respx.post("http://127.0.0.1:8000/webhooks/github").respond(
        401, json={"error": "invalid signature"}
    )
    result = runner.invoke(app, ["replay-webhook", str(payload), "--event", "push"])
    assert result.exit_code == 1 and "401" in result.output


def test_the_worker_refuses_to_start_without_a_github_app(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("NEWSOC_GITHUB_APP_ID", raising=False)
    monkeypatch.setenv("NEWSOC_ENV", "no-such-env")  # so no app.env is picked up
    get_settings.cache_clear()
    try:
        result = runner.invoke(app, ["worker"])
    finally:
        get_settings.cache_clear()
    assert result.exit_code == 2 and "NEWSOC_GITHUB_APP_ID" in result.output
