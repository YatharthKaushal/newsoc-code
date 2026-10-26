"""``newsoc`` command line: run the same scan pipeline the GitHub App runs, without GitHub.

Exit status: 0 when the check would pass (success or neutral), 1 when it would fail
(failure or action_required), 2 when newsoc itself could not run. That makes ``newsoc scan``
usable as a CI step on its own.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated

import httpx
import typer

from newsoc_code import osvdb
from newsoc_code.config import get_settings
from newsoc_code.findings import baseline as baselines
from newsoc_code.findings.schema import ScanResult
from newsoc_code.github.signature import sign
from newsoc_code.policy.engine import Conclusion, PolicyOutcome, evaluate
from newsoc_code.policy.loader import PolicyLoad, load_policy
from newsoc_code.policy.schema import Mode
from newsoc_code.report.sarif import to_sarif
from newsoc_code.runner.docker import DockerRunner, RootUserRefused, resolve_user
from newsoc_code.runner.image import ImageBuildError, ensure_image
from newsoc_code.scan import install_rules, rules_version, scan_tree
from newsoc_code.scanners.base import ScanContext, TreeInfo

app = typer.Typer(no_args_is_help=True, add_completion=False, help="newsoc Code arm")

COLOURS = {
    Conclusion.SUCCESS: "green",
    Conclusion.NEUTRAL: "yellow",
    Conclusion.FAILURE: "red",
    Conclusion.ACTION_REQUIRED: "red",
}


@app.callback()
def main() -> None:
    """newsoc Code arm: scan pushes and pull requests, gate merges by policy."""


def _default_salt() -> bytes:
    return os.environ.get("NEWSOC_FINGERPRINT_SALT", "newsoc-dev-salt-change-me").encode()


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(exists=True, file_okay=False, resolve_path=True)],
    rules: Annotated[Path | None, typer.Option(help="Semgrep rule pack directory")] = None,
    osv_db: Annotated[Path | None, typer.Option(help="Offline OSV database directory")] = None,
    policy: Annotated[Path | None, typer.Option(help=".secpolicy.yml to apply")] = None,
    enforce: Annotated[
        bool | None, typer.Option("--enforce/--observe", help="Override the policy's mode")
    ] = None,
    baseline: Annotated[
        Path | None, typer.Option(help="JSON list of fingerprints already on the base branch")
    ] = None,
    write_baseline: Annotated[
        Path | None, typer.Option(help="Save this scan's fingerprints as a baseline")
    ] = None,
    sarif: Annotated[Path | None, typer.Option(help="Write SARIF 2.1.0 here")] = None,
    json_out: Annotated[Path | None, typer.Option("--json", help="Write results as JSON")] = None,
    image: Annotated[str, typer.Option(help="Scanner image")] = "newsoc/scanners:dev",
    workers: Annotated[int, typer.Option(help="Scanners to run in parallel")] = 2,
) -> None:
    """Scan PATH with every applicable scanner, each sandboxed, then apply the policy."""
    rules_dir = rules or (Path(__file__).resolve().parents[2] / "rules" / "semgrep")
    runner = DockerRunner(image=image)
    if not runner.available():
        typer.secho(
            f"Docker image {image!r} is not available (is the daemon reachable?)",
            fg="red",
            err=True,
        )
        raise typer.Exit(2)

    with tempfile.TemporaryDirectory(prefix="newsoc-out-") as out:
        out_dir = Path(out)
        out_dir.chmod(0o777)
        ctx = ScanContext(
            src_root=path,
            out_dir=out_dir,
            tree=TreeInfo.scan(path),
            salt=_default_salt(),
            rules_dir=rules_dir if rules_dir.exists() else None,
            rules_version=rules_version(rules_dir) if rules_dir.exists() else None,
            osv_db_dir=(osvdb.current(osv_db) or osv_db) if osv_db else None,
        )
        results = scan_tree(ctx, runner, max_workers=workers)

    today = datetime.now(UTC).date()
    loaded = load_policy(policy.read_text(encoding="utf-8") if policy else None, today)
    if enforce is not None and not loaded.invalid:
        mode = Mode.ENFORCE if enforce else Mode.OBSERVE
        loaded = PolicyLoad(
            loaded.policy.model_copy(update={"mode": mode}),
            loaded.source,
            warnings=loaded.warnings,
        )
    base = baselines.load(baseline) if baseline else None
    outcome = evaluate(loaded, results, base, today)

    _print(results, outcome)
    if write_baseline:
        baselines.save(write_baseline, baselines.from_results(results))
    if sarif:
        sarif.write_text(
            json.dumps(to_sarif(results, outcome.decisions, base is not None), indent=2)
        )
    if json_out:
        json_out.write_text(json.dumps([r.model_dump(mode="json") for r in results], indent=2))
    if outcome.conclusion in (Conclusion.FAILURE, Conclusion.ACTION_REQUIRED):
        raise typer.Exit(1)


def _print(results: list[ScanResult], outcome: PolicyOutcome) -> None:
    by_fp = {d.finding.fingerprint: d for d in outcome.decisions}
    for r in results:
        colour = {"ok": "green", "not_applicable": "yellow"}.get(r.status.value, "red")
        typer.secho(
            f"{r.scanner:12} {r.status.value:15} {len(r.findings):3} finding(s)  "
            f"{r.duration_ms / 1000:5.1f}s  {r.reason or ''}",
            fg=colour,
        )
        for f in r.findings:
            tag = by_fp[f.fingerprint].outcome.value if f.fingerprint in by_fp else ""
            typer.echo(
                f"   [{f.severity.value:8}] {tag:11} {f.rule_id}  {f.path}:{f.start_line}  "
                f"{f.message[:70]}"
            )
    typer.echo()
    for note in outcome.notes:
        typer.secho(f"note: {note}", fg="yellow")
    typer.secho(
        f"Result: {outcome.conclusion.value.upper()}  {outcome.title}",
        fg=COLOURS[outcome.conclusion],
        bold=True,
    )


@app.command("refresh-osv")
def refresh_osv(
    db_root: Annotated[Path, typer.Option(help="Directory that holds OSV database snapshots")],
    image: Annotated[str, typer.Option(help="Scanner image")] = "newsoc/scanners:dev",
) -> None:
    """Download a fresh OSV database snapshot. This is the only step that needs a network."""
    snapshot = osvdb.refresh(db_root, osvdb.docker_downloader(image))
    typer.secho(f"OSV database snapshot ready: {snapshot}", fg="green")
    status = osvdb.check(snapshot)
    typer.echo(f"age {status.age.total_seconds() / 3600:.1f} h; `current` now points here")


def _logging() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)  # request lines add nothing useful


@app.command()
def serve(
    host: Annotated[
        str, typer.Option(help="Interface to bind; keep 127.0.0.1 behind a proxy")
    ] = "127.0.0.1",
    port: Annotated[int, typer.Option()] = 8000,
    migrate: Annotated[bool, typer.Option(help="Apply database migrations first")] = False,
) -> None:
    """Run the webhook receiver (the web process)."""
    import uvicorn

    _logging()
    if migrate:
        from newsoc_code.db.session import make_engine
        from newsoc_code.migrations import upgrade_to_head

        engine = make_engine(get_settings().database_url)
        upgrade_to_head(engine)
        engine.dispose()
        typer.echo("database is up to date")
    uvicorn.run("newsoc_code.app.main:create_app", factory=True, host=host, port=port)


@app.command()
def worker(
    poll: Annotated[float, typer.Option(help="Seconds to wait when the queue is empty")] = 2.0,
) -> None:
    """Run the scan worker: claims queued jobs and scans them in Docker."""
    from newsoc_code.db.session import make_engine, make_session_factory
    from newsoc_code.github.client import GitHubClient
    from newsoc_code.github.fetch import Workspace, valid_repo
    from newsoc_code.pipeline import JobProcessor
    from newsoc_code.queue.worker import Worker

    _logging()
    settings = get_settings()
    if settings.github_app_id is None:
        typer.secho(
            "NEWSOC_GITHUB_APP_ID is not set; run `newsoc create-app` first", fg="red", err=True
        )
        raise typer.Exit(2)
    image = settings.scanner_image
    try:
        resolve_user(None)  # refuse to run as root before spending minutes building an image
        if settings.scanner_dockerfile is not None:
            image = ensure_image(settings.scanner_dockerfile)
        runner = DockerRunner(image=image)
    except (RootUserRefused, ImageBuildError) as exc:
        typer.secho(str(exc), fg="red", err=True)
        raise typer.Exit(2) from exc
    if not runner.available():
        typer.secho(
            f"Docker image {image!r} is not available (is the daemon reachable?)",
            fg="red",
            err=True,
        )
        raise typer.Exit(2)
    install_rules(settings.bundled_rules_dir, settings.rules_dir)
    killed = runner.kill_orphans()  # this assumes a single worker process per host
    if killed:
        typer.echo(f"stopped {killed} scanner container(s) left by a previous worker")

    sessions = make_session_factory(make_engine(settings.database_url))
    github = GitHubClient(
        settings.github_app_id, settings.private_key(), api_url=settings.github_api_url
    )
    processor = JobProcessor(
        settings=settings,
        session_factory=sessions,
        github=github,
        runner_factory=runner.with_cancel,
        workspace_factory=lambda root, repo, token: Workspace(
            root, f"{settings.github_clone_url}/{valid_repo(repo)}.git", token
        ),
    )
    refresher = None
    if settings.osv_refresh_hours > 0:
        refresher = osvdb.Refresher(
            settings.osv_db_root,
            osvdb.docker_downloader(image),
            timedelta(hours=settings.osv_refresh_hours),
        )
    instance = Worker(
        session_factory=sessions, processor=processor, settings=settings, refresher=refresher
    )
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: instance.request_shutdown())
    typer.echo(f"worker {instance.worker_id} started")
    instance.run_forever(poll)
    typer.echo("worker stopped")


@app.command("replay-webhook")
def replay_webhook(
    payload: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    event: Annotated[str, typer.Option(help="X-GitHub-Event, e.g. pull_request")],
    url: Annotated[str, typer.Option()] = "http://127.0.0.1:8000/webhooks/github",
    delivery: Annotated[
        str | None, typer.Option(help="X-GitHub-Delivery (default: random)")
    ] = None,
) -> None:
    """Send a saved webhook payload, signed with the local webhook secret, to a running server.

    Use it to test the receiver without GitHub, or to re-send a delivery from GitHub's
    "Recent deliveries" page (copy its payload to a file).
    """
    import uuid

    body = payload.read_bytes()
    headers = {
        "content-type": "application/json",
        "x-github-event": event,
        "x-github-delivery": delivery or str(uuid.uuid4()),
        "x-hub-signature-256": sign(get_settings().webhook_secret(), body),
    }
    resp = httpx.post(url, content=body, headers=headers, timeout=30)
    typer.echo(f"{resp.status_code} {resp.text}")
    if resp.status_code >= 400:
        raise typer.Exit(1)


@app.command("create-app")
def create_app_command(
    webhook_url: Annotated[
        str, typer.Option(help="Where GitHub sends webhooks (a smee.io URL in dev)")
    ],
    name: Annotated[
        str, typer.Option(help="GitHub App name (must be unique on GitHub)")
    ] = "newsoc-dev",
    owner: Annotated[
        str | None, typer.Option(help="Organisation to own the app (default: you)")
    ] = None,
    env: Annotated[str, typer.Option(help="Names the credentials directory")] = "dev",
    force: Annotated[bool, typer.Option(help="Replace existing credentials")] = False,
) -> None:
    """Create the GitHub App in your browser and store its credentials (human step)."""
    import webbrowser

    from newsoc_code.config import _config_dir
    from newsoc_code.github import app_setup

    directory = _config_dir(env)
    if (directory / "app.pem").exists() and not force:
        typer.secho(
            f"{directory / 'app.pem'} exists; pass --force to replace it", fg="red", err=True
        )
        raise typer.Exit(1)
    server = app_setup.ManifestServer(
        lambda redirect: app_setup.build_manifest(
            name, webhook_url, redirect, "https://example.invalid/newsoc"
        ),
        owner,
        app_setup.exchange_code,
    )
    typer.echo(f"Opening {server.start_url} - confirm the app on GitHub when asked.")
    webbrowser.open(server.start_url)
    conversion = server.run()
    written = app_setup.write_credentials(directory, conversion, force=force)
    typer.secho(f"Created GitHub App {conversion['slug']!r} (id {conversion['id']}).", fg="green")
    for path in written:
        typer.echo(f"  wrote {path} (0600)")
    typer.echo(
        f"Install it on a repository: https://github.com/apps/{conversion['slug']}/installations/new"
    )
    typer.echo(f"The app id is saved in {directory / 'app.env'} and is read automatically.")


if __name__ == "__main__":
    app()
