"""Create the GitHub App through GitHub's manifest flow, then store its credentials safely.

The flow needs a human in a browser (GitHub asks you to confirm the app), so this module only
supplies the pieces: the manifest, a small localhost server that receives GitHub's redirect, the
code-for-credentials exchange, and a writer that keeps secrets out of the repository and out of
reach of other users (``~/.config/newsoc/<env>/``, files 0600, directory 0700).
"""

from __future__ import annotations

import html
import json
import os
import secrets
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx

# The least the Code arm needs. There is no Administration, Actions, Secrets or Workflows access,
# so a compromised newsoc could not change a repository's settings, CI or secrets.
PERMISSIONS = {
    "checks": "write",  # create and update check runs, with annotations
    "contents": "read",  # fetch code and read .secpolicy.yml
    "metadata": "read",
    "pull_requests": "write",  # post the summary comment
    "merge_queues": "read",  # receive merge_group events
}
EVENTS = ["pull_request", "push", "check_run", "check_suite", "merge_group"]
API = "https://api.github.com"


def build_manifest(name: str, webhook_url: str, redirect_url: str, homepage: str) -> dict[str, Any]:
    return {
        "name": name,
        "url": homepage,
        "hook_attributes": {"url": webhook_url, "active": True},
        "redirect_url": redirect_url,
        "public": False,
        "default_permissions": dict(PERMISSIONS),
        "default_events": list(EVENTS),
    }


def registration_url(owner: str | None, state: str) -> str:
    """Where the manifest is posted: a personal account, or an organisation."""
    base = (
        f"https://github.com/organizations/{owner}/settings/apps/new"
        if owner
        else "https://github.com/settings/apps/new"
    )
    return f"{base}?state={state}"


def exchange_code(
    code: str, http: httpx.Client | None = None, api_url: str = API
) -> dict[str, Any]:
    """Trade the one-time code from GitHub's redirect for the app's credentials."""
    client = http or httpx.Client(timeout=30)
    resp = client.post(
        f"{api_url}/app-manifests/{code}/conversions",
        headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"},
    )
    resp.raise_for_status()
    data = resp.json()
    for key in ("id", "slug", "pem", "webhook_secret"):
        if key not in data:
            raise ValueError(f"GitHub's response is missing {key!r}")
    return dict(data)


def write_credentials(
    directory: Path, conversion: dict[str, Any], *, force: bool = False
) -> list[Path]:
    """Store the credentials. Refuses to overwrite an existing app unless ``force`` is set."""
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o700)
    pem = directory / "app.pem"
    if pem.exists() and not force:
        raise FileExistsError(
            f"{pem} already exists; use --force to replace this app's credentials"
        )

    files = {
        "app.pem": str(conversion["pem"]),
        "webhook_secret": str(conversion["webhook_secret"]),
        "app.env": f"NEWSOC_GITHUB_APP_ID={conversion['id']}\n",
    }
    written = []
    for name, content in files.items():
        path = directory / name
        _write_private(path, content)
        written.append(path)
    salt = directory / "fingerprint_salt"
    if not salt.exists():  # never rotate it silently: it keys every stored secret fingerprint
        _write_private(salt, secrets.token_hex(32))
        written.append(salt)
    return written


def _write_private(path: Path, content: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(content)
    path.chmod(0o600)  # os.open's mode is masked by umask and ignored for existing files


class ManifestServer:
    """A one-shot localhost server: serves the form that posts the manifest to GitHub, then
    receives the redirect and exchanges its code for credentials."""

    def __init__(
        self,
        manifest_for: Callable[[str], dict[str, Any]],
        owner: str | None,
        exchange: Callable[[str], dict[str, Any]],
        port: int = 0,
    ) -> None:
        self.state = secrets.token_urlsafe(24)
        self.result: dict[str, Any] | None = None
        self.error: str | None = None
        self.done = threading.Event()
        server = self
        self._owner = owner
        self._exchange = exchange
        self.httpd = HTTPServer(("127.0.0.1", port), self._handler_class(server))
        self.redirect_url = f"http://127.0.0.1:{self.httpd.server_port}/callback"
        self.start_url = f"http://127.0.0.1:{self.httpd.server_port}/"
        self.manifest = manifest_for(self.redirect_url)

    @staticmethod
    def _handler_class(server: ManifestServer) -> type[BaseHTTPRequestHandler]:
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                return  # keep one-time codes out of terminal scrollback

            def _send(self, status: int, body: str) -> None:
                data = body.encode()
                self.send_response(status)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:
                url = urlparse(self.path)
                if url.path == "/":
                    self._send(200, server.form_page())
                elif url.path == "/callback":
                    self._callback(parse_qs(url.query))
                else:
                    self._send(404, "not found")

            def _callback(self, query: dict[str, list[str]]) -> None:
                state, code = query.get("state", [""])[0], query.get("code", [""])[0]
                if not secrets.compare_digest(state, server.state) or not code:
                    server.error = "state mismatch or missing code; start again"
                    self._send(400, "<p>Rejected: state mismatch. Start the flow again.</p>")
                    server.done.set()
                    return
                try:
                    server.result = server._exchange(code)
                except Exception as exc:
                    server.error = f"{type(exc).__name__}: {exc}"
                    self._send(502, "<p>GitHub rejected the code. See the terminal.</p>")
                else:
                    self._send(
                        200, "<p>Done. You can close this tab and go back to the terminal.</p>"
                    )
                server.done.set()

        return Handler

    def form_page(self) -> str:
        action = html.escape(registration_url(self._owner, self.state), quote=True)
        manifest = html.escape(json.dumps(self.manifest), quote=True)
        return (
            "<!doctype html><meta charset=utf-8><title>Create the newsoc GitHub App</title>"
            f'<form id=f method=post action="{action}">'
            f'<input type=hidden name=manifest value="{manifest}">'
            "<noscript><button>Continue to GitHub</button></noscript></form>"
            "<p>Sending the app manifest to GitHub&hellip;</p>"
            "<script>document.getElementById('f').submit()</script>"
        )

    def run(self, timeout_s: float = 600) -> dict[str, Any]:
        thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        thread.start()
        try:
            if not self.done.wait(timeout_s):
                raise TimeoutError("no response from GitHub within the time limit")
        finally:
            self.httpd.shutdown()
            self.httpd.server_close()
        if self.result is None:
            raise RuntimeError(self.error or "the app was not created")
        return self.result
