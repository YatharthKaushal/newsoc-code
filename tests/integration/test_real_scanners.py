"""Real scanners in the real sandbox, over deterministic fixture projects."""

from __future__ import annotations

import json
import os
from pathlib import Path

import builders as fx
import pytest

from newsoc_code.findings.schema import ScanStatus, Severity
from newsoc_code.runner.docker import DockerRunner
from newsoc_code.scan import run_adapter, scan_tree
from newsoc_code.scanners.checkov import CheckovAdapter
from newsoc_code.scanners.gitleaks import GitleaksAdapter
from newsoc_code.scanners.osv import OsvAdapter

pytestmark = pytest.mark.docker


@pytest.fixture(scope="module")
def runner() -> DockerRunner:
    return DockerRunner()


def test_gitleaks_finds_seeded_secrets_without_leaking_them(tmp_path, runner, make_ctx):
    fx.make_js_app(tmp_path)
    result = run_adapter(GitleaksAdapter(), make_ctx(tmp_path), runner)

    assert result.status is ScanStatus.OK, result.reason
    rules = {f.rule_id for f in result.findings}
    assert {"aws-access-token", "github-pat"} <= rules
    dumped = json.dumps(result.model_dump(mode="json"))
    for secret in (fx.AWS_KEY, fx.AWS_SECRET, fx.GITHUB_TOKEN):
        assert secret not in dumped
    assert not (make_ctx(tmp_path).out_dir / "gitleaks.json").exists()


def test_gitleaks_history_mode_still_blocks_a_secret_that_was_later_deleted(
    tmp_path, runner, make_ctx
):
    repo = tmp_path / "repo"
    fx.make_js_app(repo)
    fx.init_repo(repo)
    fx.commit_all(repo, "add app with secrets")
    (repo / "src" / "config.js").write_text("module.exports = {};\n")
    fx.commit_all(repo, "remove secrets")

    working_tree = run_adapter(GitleaksAdapter(), make_ctx(repo), runner)
    history = run_adapter(
        GitleaksAdapter(), make_ctx(repo, gitleaks_mode="git", gitleaks_log_opts="--all"), runner
    )

    assert working_tree.status is ScanStatus.OK
    assert history.status is ScanStatus.OK
    assert not any(f.rule_id == "github-pat" for f in working_tree.findings)  # gone from the tree
    assert any(f.rule_id == "github-pat" for f in history.findings)  # but still in history
    assert all(f.extra["history_commit"] for f in history.findings)


def test_gitleaks_clean_repository_is_ok_with_no_findings(tmp_path, runner, make_ctx):
    fx.make_clean_app(tmp_path)
    result = run_adapter(GitleaksAdapter(), make_ctx(tmp_path), runner)
    assert result.status is ScanStatus.OK
    assert result.findings == []
    assert result.assessment().value == "Verified"


def test_checkov_flags_the_seeded_misconfigurations(tmp_path, runner, make_ctx):
    fx.make_tf_infra(tmp_path)
    result = run_adapter(CheckovAdapter(), make_ctx(tmp_path), runner)

    assert result.status is ScanStatus.OK, result.reason
    by_id = {f.rule_id: f for f in result.findings}
    assert by_id["CKV_AWS_24"].severity is Severity.HIGH  # SSH open to the world
    assert by_id["CKV_AWS_20"].severity is Severity.HIGH  # public-read bucket
    assert by_id["CKV_DOCKER_7"].path == "Dockerfile"


def test_checkov_is_not_applicable_without_infrastructure_files(tmp_path, runner, make_ctx):
    fx.make_clean_app(tmp_path)
    result = run_adapter(CheckovAdapter(), make_ctx(tmp_path), runner)
    assert result.status is ScanStatus.NOT_APPLICABLE


@pytest.mark.skipif(
    not os.environ.get("NEWSOC_OSV_DB"), reason="set NEWSOC_OSV_DB to an offline OSV database"
)
def test_osv_offline_finds_vulnerable_dependencies(tmp_path, runner, make_ctx):
    fx.make_js_app(tmp_path)
    fx.make_py_app(tmp_path)
    ctx = make_ctx(tmp_path, osv_db_dir=Path(os.environ["NEWSOC_OSV_DB"]))
    result = run_adapter(OsvAdapter(), ctx, runner)

    assert result.status is ScanStatus.OK, result.reason
    packages = {f.extra["package"] for f in result.findings}
    assert {"lodash", "minimist", "express", "flask", "pyyaml", "requests"} <= packages
    assert any(f.severity is Severity.CRITICAL for f in result.findings)


def test_one_broken_scanner_does_not_hide_the_others(tmp_path, runner, make_ctx):
    """Missing OSV database: SCA fails loudly while the other categories are still assessed."""
    fx.make_mixed(tmp_path)
    ctx = make_ctx(tmp_path, osv_db_dir=None)
    results = {r.scanner: r for r in scan_tree(ctx, runner)}

    assert results["osv-scanner"].status is ScanStatus.FAILED
    assert results["gitleaks"].status is ScanStatus.OK
    assert results["checkov"].status is ScanStatus.OK
