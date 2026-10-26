"""A scanner that crashes, hangs or writes garbage must never look like "no findings"."""

from __future__ import annotations

import builders as fx
import pytest

from newsoc_code.findings.schema import ScanStatus
from newsoc_code.scanners.checkov import CheckovAdapter
from newsoc_code.scanners.gitleaks import GitleaksAdapter
from newsoc_code.scanners.osv import OsvAdapter
from newsoc_code.scanners.semgrep import SemgrepAdapter
from tests.conftest import run_output

# (adapter, report file name, exit codes that are normal for that tool)
CASES = [
    (SemgrepAdapter(), "semgrep.json", (0,)),
    (OsvAdapter(), "osv.json", (0, 1)),
    (GitleaksAdapter(), "gitleaks.json", (0, 1)),
    (CheckovAdapter(), "results_json.json", (0,)),
]
IDS = [c[0].name for c in CASES]


@pytest.fixture
def src(tmp_path):
    fx.make_mixed(tmp_path)
    return tmp_path


@pytest.mark.parametrize(("adapter", "report", "ok_codes"), CASES, ids=IDS)
def test_timeout_is_reported_as_timeout(adapter, report, ok_codes, src, make_ctx):
    result = adapter.parse(make_ctx(src), run_output(None, timed_out=True))
    assert result.status is ScanStatus.TIMEOUT
    assert not result.assessed
    assert result.assessment().value == "Not assessed"


@pytest.mark.parametrize(("adapter", "report", "ok_codes"), CASES, ids=IDS)
def test_oom_kill_is_a_failure(adapter, report, ok_codes, src, make_ctx):
    result = adapter.parse(make_ctx(src), run_output(137))
    assert result.status is ScanStatus.FAILED


@pytest.mark.parametrize(("adapter", "report", "ok_codes"), CASES, ids=IDS)
def test_unexpected_exit_status_is_a_failure(adapter, report, ok_codes, src, make_ctx):
    result = adapter.parse(make_ctx(src), run_output(2, stderr="boom"))
    assert result.status is ScanStatus.FAILED
    assert result.stderr_tail == "boom"


@pytest.mark.parametrize(("adapter", "report", "ok_codes"), CASES, ids=IDS)
def test_truncated_json_is_a_failure(adapter, report, ok_codes, src, make_ctx):
    ctx = make_ctx(src)
    (ctx.out_dir / report).write_text('{"results": [{"check_id": "x"', encoding="utf-8")
    result = adapter.parse(ctx, run_output(ok_codes[0]))
    assert result.status is ScanStatus.FAILED
    assert result.findings == []


@pytest.mark.parametrize(
    ("adapter", "report", "ok_codes"),
    [c for c in CASES if c[0].name != "gitleaks"],
    ids=[n for n in IDS if n != "gitleaks"],
)
def test_missing_report_is_a_failure(adapter, report, ok_codes, src, make_ctx):
    result = adapter.parse(make_ctx(src), run_output(ok_codes[0]))
    assert result.status is ScanStatus.FAILED


def test_gitleaks_without_a_report_and_exit_zero_means_clean(src, make_ctx):
    # Gitleaks writes nothing when it finds nothing; that is the one legitimate empty case.
    result = GitleaksAdapter().parse(make_ctx(src), run_output(0))
    assert result.status is ScanStatus.OK and result.findings == []


def test_gitleaks_exit_one_without_a_report_is_a_failure(src, make_ctx):
    # "Leaks found" but nothing to read: we must not report a clean result.
    result = GitleaksAdapter().parse(make_ctx(src), run_output(1))
    assert result.status is ScanStatus.FAILED


def test_osv_no_package_sources_is_not_applicable(src, make_ctx):
    result = OsvAdapter().parse(
        make_ctx(src), run_output(128, stderr="No package sources found, --help")
    )
    assert result.status is ScanStatus.NOT_APPLICABLE


def test_a_scanner_that_raises_becomes_a_failed_result(src, make_ctx):
    from newsoc_code.runner.base import RunSpec
    from newsoc_code.scan import run_adapter

    class Boom:
        def run(self, spec: RunSpec):
            raise RuntimeError("docker exploded")

    ctx = make_ctx(src)
    result = run_adapter(SemgrepAdapter(), ctx, Boom())
    assert result.status is ScanStatus.FAILED
    assert "docker exploded" in (result.reason or "")


def test_missing_rule_pack_is_a_failure_not_a_skip(src, make_ctx):
    from newsoc_code.runner.local import LocalRunner
    from newsoc_code.scan import run_adapter

    ctx = make_ctx(src, rules_dir=None)
    result = run_adapter(SemgrepAdapter(), ctx, LocalRunner())
    assert result.status is ScanStatus.FAILED
    assert "rule pack" in (result.reason or "")
