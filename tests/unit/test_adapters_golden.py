"""Each adapter parses real (trimmed) scanner output into the expected findings."""

from __future__ import annotations

import json

import builders as fx

from newsoc_code.findings.schema import Confidence, ScanStatus, Severity
from newsoc_code.scanners.checkov import CheckovAdapter
from newsoc_code.scanners.gitleaks import GitleaksAdapter
from newsoc_code.scanners.osv import OsvAdapter
from newsoc_code.scanners.semgrep import SemgrepAdapter
from tests.conftest import run_output


def test_semgrep_golden(tmp_path, make_ctx, place_report):
    fx.make_py_app(tmp_path)
    ctx = make_ctx(tmp_path)
    place_report(ctx, "semgrep/py-shell-true.json", "semgrep.json")

    result = SemgrepAdapter().parse(ctx, run_output(0))

    assert result.status is ScanStatus.OK
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.rule_id == "newsoc.probe.py-shell-true"  # config-path prefix stripped
    assert f.path == "app.py"  # container path mapped to repository-relative
    assert f.start_line == 12
    assert f.severity is Severity.HIGH  # ERROR maps to high when the rule gives no severity
    assert f.confidence is Confidence.HIGH
    assert f.cwe == ("CWE-78",)
    assert any("shell=True" in line for line in f.evidence)  # evidence read from our checkout
    assert f.rule_version == "testpack1"
    assert f.scanner_version == "1.182.1"


def test_osv_golden(tmp_path, make_ctx, place_report):
    fx.make_js_app(tmp_path)
    fx.make_py_app(tmp_path)
    ctx = make_ctx(tmp_path)
    place_report(ctx, "osv/npm-and-pypi.json", "osv.json")

    result = OsvAdapter().parse(ctx, run_output(1))  # exit 1 means "vulnerabilities found"

    assert result.status is ScanStatus.OK
    by_pkg: dict[str, list] = {}
    for f in result.findings:
        by_pkg.setdefault(f.extra["package"], []).append(f)
    assert set(by_pkg) == {"lodash", "pyyaml"}
    assert {f.path for f in by_pkg["lodash"]} == {"package-lock.json"}
    assert {f.path for f in by_pkg["pyyaml"]} == {"requirements.txt"}
    assert all(f.confidence is Confidence.HIGH for f in result.findings)  # exact lockfile versions
    assert all(
        f.rule_id.startswith("CVE-") for f in result.findings
    )  # CVE preferred as canonical id
    assert all(len(f.vuln_ids) >= 2 for f in result.findings)  # GHSA alias kept alongside the CVE
    assert any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in result.findings)
    assert all(f.start_line >= 1 for f in result.findings)
    # one finding per advisory group, never one per alias
    assert len({f.fingerprint for f in result.findings}) == len(result.findings)


def test_checkov_golden(tmp_path, make_ctx, place_report):
    fx.make_tf_infra(tmp_path)
    ctx = make_ctx(tmp_path)
    place_report(ctx, "checkov/terraform-and-docker.json", "results_json.json")

    result = CheckovAdapter().parse(ctx, run_output(0))

    assert result.status is ScanStatus.OK
    by_id = {f.rule_id: f for f in result.findings}
    assert len(by_id) == 6
    assert by_id["CKV_AWS_24"].severity is Severity.HIGH  # open SSH ingress: curated
    assert by_id["CKV_AWS_24"].confidence is Confidence.HIGH
    assert by_id["CKV_AWS_23"].severity is Severity.LOW  # description hygiene: curated low
    assert by_id["CKV2_AWS_5"].severity is Severity.MEDIUM  # not curated: default
    assert by_id["CKV2_AWS_5"].confidence is Confidence.MEDIUM
    assert by_id["CKV_AWS_24"].path == "main.tf"
    assert by_id["CKV_DOCKER_7"].path == "Dockerfile"
    assert by_id["CKV_AWS_24"].start_line == 6 and by_id["CKV_AWS_24"].end_line == 15


def test_gitleaks_golden_groups_one_secret_into_one_finding(tmp_path, make_ctx, place_report):
    ctx = make_ctx(tmp_path)
    report = place_report(ctx, "gitleaks/two-secrets-one-repeated.json", "gitleaks.json")

    result = GitleaksAdapter().parse(ctx, run_output(1))

    assert result.status is ScanStatus.OK
    assert len(result.findings) == 2  # three leak records, but one secret appears twice
    pat = next(f for f in result.findings if f.rule_id == "github-pat")
    assert pat.severity is Severity.CRITICAL
    assert pat.path == "src/config.js"
    assert pat.extra["other_locations"] == [{"path": "scripts/deploy.js", "line": 9}]
    generic = next(f for f in result.findings if f.rule_id == "generic-api-key")
    assert generic.confidence is Confidence.MEDIUM  # entropy-style rule: not trusted to block alone
    assert not report.exists(), (
        "the raw report holds secret values and must be deleted after parsing"
    )


def test_gitleaks_never_stores_or_prints_the_secret_value(tmp_path, make_ctx, place_report):
    ctx = make_ctx(tmp_path)
    place_report(ctx, "gitleaks/two-secrets-one-repeated.json", "gitleaks.json")

    result = GitleaksAdapter().parse(ctx, run_output(1))

    dumped = json.dumps(result.model_dump(mode="json"))
    assert "SYNTHETIC-SECRET-VALUE-ONE-0000000001" not in dumped
    assert "SYNTHETIC-SECRET-VALUE-TWO-0000000002" not in dumped
    assert all("[REDACTED]" in f.evidence[0] for f in result.findings)


def test_gitleaks_fingerprint_depends_on_the_salt_not_on_the_path(tmp_path, make_ctx, place_report):
    ctx_a = make_ctx(tmp_path)
    place_report(ctx_a, "gitleaks/two-secrets-one-repeated.json", "gitleaks.json")
    a = GitleaksAdapter().parse(ctx_a, run_output(1))
    ctx_b = make_ctx(tmp_path, salt=b"another-salt")
    place_report(ctx_b, "gitleaks/two-secrets-one-repeated.json", "gitleaks.json")
    b = GitleaksAdapter().parse(ctx_b, run_output(1))

    assert {f.fingerprint for f in a.findings}.isdisjoint({f.fingerprint for f in b.findings})
