"""Run every applicable scanner on a checkout and collect normalised results."""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from newsoc_code.findings.schema import ScanResult, ScanStatus
from newsoc_code.runner.base import Runner
from newsoc_code.scanners.base import ScanContext, ScannerAdapter
from newsoc_code.scanners.checkov import CheckovAdapter
from newsoc_code.scanners.gitleaks import GitleaksAdapter
from newsoc_code.scanners.osv import OsvAdapter
from newsoc_code.scanners.semgrep import SemgrepAdapter

log = logging.getLogger(__name__)


def default_adapters() -> list[ScannerAdapter]:
    return [SemgrepAdapter(), OsvAdapter(), GitleaksAdapter(), CheckovAdapter()]


def rules_version(rules_dir: Path) -> str:
    """A short content hash of the rule pack, recorded on every finding it produces."""
    digest = hashlib.sha256()
    for path in sorted(p for p in rules_dir.rglob("*") if p.is_file()):
        digest.update(path.relative_to(rules_dir).as_posix().encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()[:12]


def install_rules(source: Path, dest: Path) -> Path:
    """Copy the bundled rule pack to ``dest``, replacing what is there.

    Scanner containers are started by the Docker host, which mounts the rules from a HOST path.
    A containerised worker therefore copies them into a directory it shares with the host at the
    same path. A no-op when source and destination are the same directory.
    """
    if source.resolve() == dest.resolve():
        return dest
    staging = dest.with_name(dest.name + ".new")
    shutil.rmtree(staging, ignore_errors=True)
    shutil.copytree(source, staging)
    for path in [staging, *staging.rglob("*")]:
        path.chmod(0o755 if path.is_dir() else 0o644)  # readable by the unprivileged scanners
    shutil.rmtree(dest, ignore_errors=True)
    os.replace(staging, dest)
    return dest


def run_adapter(adapter: ScannerAdapter, ctx: ScanContext, runner: Runner) -> ScanResult:
    """One scanner, start to finish. Never raises: any problem becomes a failed result."""
    try:
        if (reason := adapter.applicable(ctx)) is not None:
            return adapter.not_applicable(reason)
        run = runner.run(adapter.spec(ctx))
        return adapter.parse(ctx, run)
    except Exception as exc:  # a scanner problem must never become a silent "no findings"
        log.exception("scanner %s failed", adapter.name)
        return ScanResult(
            scanner=adapter.name,
            category=adapter.category,
            status=ScanStatus.FAILED,
            reason=f"internal error: {type(exc).__name__}: {exc}",
        )


def scan_tree(
    ctx: ScanContext,
    runner: Runner,
    adapters: Sequence[ScannerAdapter] | None = None,
    max_workers: int = 2,
) -> list[ScanResult]:
    chosen = list(adapters) if adapters is not None else default_adapters()
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        return list(pool.map(lambda a: run_adapter(a, ctx, runner), chosen))
