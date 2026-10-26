from __future__ import annotations

import json
import stat
import threading
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from newsoc_code.github import app_setup

CONVERSION = {
    "id": 12345,
    "slug": "newsoc-dev",
    "pem": "-----BEGIN RSA PRIVATE KEY-----\nFAKE\n-----END RSA PRIVATE KEY-----\n",
    "webhook_secret": "whsec_fake",
    "client_secret": "must-not-be-stored",
}


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


# ---- the manifest ----------------------------------------------------------------------------


def test_manifest_asks_for_the_least_access_that_works() -> None:
    manifest = app_setup.build_manifest(
        "newsoc-dev", "https://smee.io/x", "http://127.0.0.1:1/c", "https://e.test"
    )
    assert manifest["default_permissions"] == {
        "checks": "write",
        "contents": "read",
        "metadata": "read",
        "pull_requests": "write",
        "merge_queues": "read",
    }
    assert set(manifest["default_events"]) == {
        "pull_request", "push", "check_run", "check_suite", "merge_group",
    }  # fmt: skip
    assert manifest["public"] is False
    assert manifest["hook_attributes"] == {"url": "https://smee.io/x", "active": True}


@pytest.mark.parametrize(
    "forbidden",
    ["administration", "actions", "secrets", "workflows", "members", "organization_administration"],
)
def test_manifest_never_requests_powerful_permissions(forbidden: str) -> None:
    manifest = app_setup.build_manifest(
        "n", "https://w.test", "http://127.0.0.1:1/c", "https://e.test"
    )
    assert forbidden not in manifest["default_permissions"]


def test_only_checks_and_pull_requests_are_writable() -> None:
    manifest = app_setup.build_manifest(
        "n", "https://w.test", "http://127.0.0.1:1/c", "https://e.test"
    )
    writable = {k for k, v in manifest["default_permissions"].items() if v == "write"}
    assert writable == {"checks", "pull_requests"}


def test_registration_url_for_a_user_and_an_organisation() -> None:
    assert app_setup.registration_url(None, "s1") == "https://github.com/settings/apps/new?state=s1"
    assert (
        app_setup.registration_url("acme", "s1")
        == "https://github.com/organizations/acme/settings/apps/new?state=s1"
    )


# ---- storing credentials ---------------------------------------------------------------------


def test_credentials_are_private_and_complete(tmp_path: Path) -> None:
    directory = tmp_path / "newsoc" / "dev"
    written = app_setup.write_credentials(directory, CONVERSION)

    assert mode(directory) == 0o700
    assert {p.name for p in written} == {"app.pem", "webhook_secret", "app.env", "fingerprint_salt"}
    for path in written:
        assert mode(path) == 0o600
    assert (directory / "app.pem").read_text() == CONVERSION["pem"]
    assert (directory / "webhook_secret").read_text() == "whsec_fake"
    assert (directory / "app.env").read_text() == "NEWSOC_GITHUB_APP_ID=12345\n"
    assert len((directory / "fingerprint_salt").read_text()) == 64
    assert "must-not-be-stored" not in "".join(p.read_text() for p in directory.iterdir())


def test_existing_credentials_are_not_overwritten_without_force(tmp_path: Path) -> None:
    app_setup.write_credentials(tmp_path, CONVERSION)
    with pytest.raises(FileExistsError):
        app_setup.write_credentials(tmp_path, {**CONVERSION, "id": 999})
    assert "12345" in (tmp_path / "app.env").read_text()


def test_replacing_an_app_keeps_the_fingerprint_salt(tmp_path: Path) -> None:
    """The salt keys every stored secret fingerprint, so a new app must not rotate it."""
    app_setup.write_credentials(tmp_path, CONVERSION)
    salt = (tmp_path / "fingerprint_salt").read_text()
    app_setup.write_credentials(tmp_path, {**CONVERSION, "id": 999}, force=True)
    assert (tmp_path / "fingerprint_salt").read_text() == salt
    assert "999" in (tmp_path / "app.env").read_text()


def test_a_pre_existing_loose_file_is_tightened(tmp_path: Path) -> None:
    (tmp_path / "webhook_secret").write_text("old")
    (tmp_path / "webhook_secret").chmod(0o644)
    app_setup.write_credentials(tmp_path, CONVERSION)
    assert mode(tmp_path / "webhook_secret") == 0o600


# ---- exchanging the code ---------------------------------------------------------------------


@respx.mock
def test_exchange_posts_the_code_and_returns_credentials() -> None:
    route = respx.post("https://api.github.com/app-manifests/abc123/conversions").respond(
        201, json=CONVERSION
    )
    assert app_setup.exchange_code("abc123")["slug"] == "newsoc-dev"
    assert route.called


@respx.mock
def test_exchange_rejects_an_incomplete_response() -> None:
    respx.post("https://api.github.com/app-manifests/abc/conversions").respond(201, json={"id": 1})
    with pytest.raises(ValueError, match="missing"):
        app_setup.exchange_code("abc")


@respx.mock
def test_exchange_surfaces_a_github_error() -> None:
    respx.post("https://api.github.com/app-manifests/bad/conversions").respond(404, json={})
    with pytest.raises(httpx.HTTPStatusError):
        app_setup.exchange_code("bad")


# ---- the localhost server --------------------------------------------------------------------


def make_server(exchange: Any, owner: str | None = None) -> app_setup.ManifestServer:
    return app_setup.ManifestServer(
        lambda redirect: app_setup.build_manifest(
            "n", "https://w.test", redirect, "https://e.test"
        ),
        owner,
        exchange,
    )


def run_in_thread(server: app_setup.ManifestServer) -> dict[str, Any]:
    outcome: dict[str, Any] = {}

    def target() -> None:
        try:
            outcome["result"] = server.run(timeout_s=10)
        except Exception as exc:
            outcome["error"] = exc

    thread = threading.Thread(target=target)
    thread.start()
    outcome["thread"] = thread
    return outcome


def test_server_listens_only_on_localhost() -> None:
    server = make_server(lambda code: {})
    assert server.httpd.server_address[0] == "127.0.0.1"
    server.httpd.server_close()


def test_start_page_posts_the_manifest_to_github_with_the_state() -> None:
    server = make_server(lambda code: {}, owner="acme")
    outcome = run_in_thread(server)
    page = httpx.get(server.start_url).text
    assert f"https://github.com/organizations/acme/settings/apps/new?state={server.state}" in page
    assert "&quot;default_permissions&quot;" in page  # the manifest is HTML-escaped into the form
    server.done.set()
    outcome["thread"].join(timeout=10)


def test_a_valid_callback_exchanges_the_code_once() -> None:
    seen: list[str] = []

    def exchange(code: str) -> dict[str, Any]:
        seen.append(code)
        return CONVERSION

    server = make_server(exchange)
    outcome = run_in_thread(server)
    resp = httpx.get(server.redirect_url, params={"code": "c0de", "state": server.state})
    outcome["thread"].join(timeout=10)

    assert resp.status_code == 200
    assert seen == ["c0de"] and outcome["result"]["slug"] == "newsoc-dev"


def test_a_callback_with_the_wrong_state_is_rejected_without_exchanging() -> None:
    seen: list[str] = []
    server = make_server(lambda code: seen.append(code) or {})  # type: ignore[func-returns-value]
    outcome = run_in_thread(server)
    resp = httpx.get(server.redirect_url, params={"code": "stolen", "state": "forged"})
    outcome["thread"].join(timeout=10)

    assert resp.status_code == 400
    assert seen == [] and "state" in str(outcome["error"])


def test_a_failing_exchange_is_reported() -> None:
    def exchange(code: str) -> dict[str, Any]:
        raise httpx.HTTPError("boom")

    server = make_server(exchange)
    outcome = run_in_thread(server)
    resp = httpx.get(server.redirect_url, params={"code": "x", "state": server.state})
    outcome["thread"].join(timeout=10)

    assert resp.status_code == 502 and "boom" in str(outcome["error"])


def test_the_form_escapes_a_hostile_manifest() -> None:
    server = app_setup.ManifestServer(
        lambda redirect: {"name": '"><script>alert(1)</script>'}, None, lambda code: {}
    )
    page = server.form_page()
    server.httpd.server_close()
    assert "<script>alert(1)" not in page
    assert json.dumps({"name": '"><script>alert(1)</script>'}) not in page
