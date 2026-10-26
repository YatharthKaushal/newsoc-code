"""Run every applicable scanner on a checkout and collect normalised results."""

from __future__ import annotations

import hashlib
import logging
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
