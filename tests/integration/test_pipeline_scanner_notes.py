"""A note written by a scanner adapter reaches the published check run and the CLI output."""

from __future__ import annotations

import pytest
from pipeline_harness import ENFORCE, Harness

from newsoc_code.findings.schema import Category, ScanResult
from newsoc_code.runner.base import RunOutput, RunSpec
from newsoc_code.scanners.base import ScanContext, ScannerAdapter

pytestmark = pytest.mark.pg

NOTE = "3 file(s) were only partly parsed, so findings in them may be missing: a.tsx, b.tsx"


class NotingScanner(ScannerAdapter):
    """Finishes cleanly but says something about its run."""

    name = "marker-notes"
    category = Category.SECRETS
    pinned_version = "0.0.1"

    def applicable(self, ctx: ScanContext) -> str | None:
        return None

    def spec(self, ctx: ScanContext) -> RunSpec:
        return RunSpec(name="notes", argv=("true",))

    def parse(self, ctx: ScanContext, run: RunOutput) -> ScanResult:
        return self.ok(run, [], notes=[NOTE])


def test_a_scanner_note_is_in_the_published_check_summary(h: Harness) -> None:
    base = h.base_commit()
    head = h.branch_commit({"a.js": "1\n"})
    h.extra_adapters.append(NotingScanner())
    h.gh.set_policy(ENFORCE)
    h.queue_pr(7, head, base)

    h.run()

    summary = h.gh.check["summary"]
    assert h.gh.check["conclusion"] == "success"  # a note is information, it does not gate
    assert "### Notes" in summary
    assert f"- {NOTE}" in summary
    assert summary.count(NOTE) == 1
