"""The job pipeline with the real scanners in real Docker containers.

This proves what fake scanners cannot: that the checkout the pipeline builds (a shallow clone, a
detached worktree for the base, `.git` mounted read-only) works inside the sandbox, that Gitleaks
reads the commit range, and that a pull request's findings come out as expected end to end.
GitHub is still fake, and the repository is a local one.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from builders import GITHUB_TOKEN
from pipeline_harness import ENFORCE, Harness, build_harness
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from newsoc_code import osvdb
from newsoc_code.db.models import ScannerRun, Trigger
from newsoc_code.runner.docker import DockerRunner
from newsoc_code.scan import default_adapters

pytestmark = [pytest.mark.docker, pytest.mark.pg]

ROOT = Path(__file__).resolve().parents[2]
OSV_ROOT = Path.home() / ".local" / "share" / "newsoc" / "osvdb"

INJECTION = """const { exec } = require('child_process');
function run(req, res) {
  exec('ls ' + req.query.dir, (e, out) => res.send(out));
}
module.exports = run;
"""
CONFIG_WITH_TOKEN = f"module.exports = {{ token: '{GITHUB_TOKEN}' }};\n"


@pytest.fixture
def real(tmp_path: Path, db: sessionmaker[Session], private_key: str) -> Harness:
    if osvdb.current(OSV_ROOT) is None:
        pytest.skip(f"no OSV snapshot under {OSV_ROOT}; run `newsoc refresh-osv`")
    docker = DockerRunner()
    return build_harness(
        tmp_path,
        db,
        private_key,
        settings_overrides={"rules_dir": ROOT / "rules" / "semgrep", "osv_db_root": OSV_ROOT},
        adapters=default_adapters,
        real_runner=docker.with_cancel,
    )


def scanner_statuses(h: Harness, job_id: int) -> dict[str, str]:
    with h.db() as s:
        rows = s.scalars(select(ScannerRun).where(ScannerRun.job_id == job_id))
        return {r.scanner: r.status for r in rows}


def test_a_clean_pull_request_passes_with_every_real_scanner(real: Harness) -> None:
    base = real.base_commit({"package.json": '{"name": "app", "version": "1.0.0"}\n'})
    head = real.branch_commit({"util.js": "module.exports = (a, b) => a + b;\n"})
    real.gh.set_policy(ENFORCE)
    job_id = real.queue_pr(7, head, base)

    real.run()

    job = real.job(job_id)
    assert (job.status, job.conclusion) == ("done", "success"), real.gh.check["summary"]
    assert real.findings(job_id) == []
    statuses = scanner_statuses(real, job_id)
    assert statuses["semgrep"] == "ok" and statuses["gitleaks"] == "ok"
    assert real.leftovers() == []
    assert (job.finished_at - job.started_at).total_seconds() < 120  # target: p50 under 3 minutes


def test_real_scanners_block_an_injection_and_a_secret_that_was_deleted_again(
    real: Harness,
) -> None:
    base = real.base_commit({"package.json": '{"name": "app", "version": "1.0.0"}\n'})
    real.branch_commit({"routes.js": INJECTION})
    real.branch_commit({"config.js": CONFIG_WITH_TOKEN})  # a token is committed ...
    head = real.branch_commit({"config.js": None})  # ... and removed in the next commit
    real.gh.set_policy(ENFORCE)
    job_id = real.queue_pr(7, head, base)

    real.run()

    check = real.gh.check
    assert check["conclusion"] == "failure", check["summary"]
    by_category = {f.category: f for f in real.findings(job_id)}
    assert by_category["sast"].rule_id == "newsoc.js.command-injection"
    assert (by_category["sast"].path, by_category["sast"].outcome) == ("routes.js", "blocked")

    secret = by_category["secrets"]  # found in history although absent from the final tree
    assert (secret.path, secret.outcome, secret.severity) == ("config.js", "blocked", "critical")
    everything = repr([(f.message, f.evidence, f.extra) for f in real.findings(job_id)])
    assert GITHUB_TOKEN not in everything  # the secret's value is never stored
    assert GITHUB_TOKEN not in check["summary"]
    assert all(GITHUB_TOKEN not in c["body"] for c in real.gh.comments.values())
    assert all(GITHUB_TOKEN not in repr(a) for a in check["annotations"])


def test_existing_injection_on_the_base_branch_is_not_reported_as_new(real: Harness) -> None:
    base = real.base_commit({"routes.js": INJECTION})
    head = real.branch_commit({"routes.js": "// reviewed\n" + INJECTION})  # lines shift down
    real.gh.set_policy(ENFORCE)
    job_id = real.queue_pr(7, head, base)

    real.run()

    assert real.gh.check["conclusion"] == "success", real.gh.check["summary"]
    assert [f.outcome for f in real.findings(job_id)] == ["baselined"]


def test_a_default_branch_push_warms_the_baseline_for_later_pull_requests(real: Harness) -> None:
    base = real.base_commit({"routes.js": INJECTION})
    real.gh.set_policy(ENFORCE)
    push_id = real.enqueue(trigger=Trigger.PUSH, head_sha=base)
    real.run()
    assert real.job(push_id).status == "done" and real.gh.check_runs == {}

    head = real.branch_commit({"routes.js": "// moved\n" + INJECTION})
    job_id = real.queue_pr(7, head, base)
    real.run()

    assert real.gh.check["conclusion"] == "success"
    assert [f.outcome for f in real.findings(job_id)] == ["baselined"]
