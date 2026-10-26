"""Real Gitleaks and Semgrep in the sandbox: lock-file checksum noise and partial parses.

The fixtures are synthetic and built at test time. Checksums are SHA-1 digests of pod names and
tokens are assembled from fragments, so no secret-shaped literal exists in this file.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import builders as fx
import pytest

from newsoc_code.findings.schema import ScanStatus
from newsoc_code.runner.docker import DockerRunner
from newsoc_code.scan import run_adapter
from newsoc_code.scanners.gitleaks import GitleaksAdapter
from newsoc_code.scanners.semgrep import SemgrepAdapter

pytestmark = pytest.mark.docker

RULES = Path(__file__).parents[2] / "rules" / "semgrep"
PODS = ("AppAuth", "GTMAppAuth", "React-cxxstableapi", "FirebaseAuth", "GoogleSignIn")
# A second GitHub-token-shaped value, so it differs from fx.GITHUB_TOKEN.
LOCKFILE_TOKEN = "ghp_" + "Q4nB8vXc2LzT6mWj9RdK1sEy7HfA5uPg3ZxV"


def checksum(name: str) -> str:
    return hashlib.sha1(name.encode()).hexdigest()


@pytest.fixture(scope="module")
def runner() -> DockerRunner:
    return DockerRunner()


def make_ios_repo(root: Path) -> None:
    """A Podfile.lock-like manifest, plus one real-looking token in it and one in source."""
    spec_checksums = "\n".join(f"  {pod}: {checksum(pod)}" for pod in PODS)
    fx.write(
        root / "ios" / "Podfile.lock",
        "PODS:\n  - AppAuth (1.7.5)\n\n"
        f"SPEC CHECKSUMS:\n{spec_checksums}\n\n"
        f"PODFILE CHECKSUM: {checksum('Podfile')}\n\n"
        f"# registry login used by CI: {LOCKFILE_TOKEN}\n"
        "COCOAPODS: 1.15.2\n",
    )
    fx.write(
        root / "src" / "deploy.js",
        f'const token = "{fx.GITHUB_TOKEN}";\nmodule.exports = {{ token }};\n',
    )


def assert_noise_gone_but_tokens_kept(result) -> None:
    assert result.status is ScanStatus.OK, result.reason
    dumped = json.dumps(result.model_dump(mode="json"))
    assert not any(checksum(pod) in dumped for pod in PODS)
    # The token in source and the one inside the manifest are still reported.
    by_path = {(f.path, f.rule_id) for f in result.findings}
    assert ("src/deploy.js", "github-pat") in by_path
    assert ("ios/Podfile.lock", "github-pat") in by_path
    # No SPEC CHECKSUMS line is reported by the entropy rule...
    assert not any(
        f.path == "ios/Podfile.lock" and f.rule_id == "generic-api-key" for f in result.findings
    )
    # ...and the note proves Gitleaks did report them, so this test is not passing vacuously.
    [note] = result.notes
    assert "generic-api-key match(es)" in note and "ios/Podfile.lock" in note
    assert fx.GITHUB_TOKEN not in dumped and LOCKFILE_TOKEN not in dumped


def test_gitleaks_ignores_podfile_lock_checksums_but_keeps_real_tokens(tmp_path, runner, make_ctx):
    make_ios_repo(tmp_path)

    result = run_adapter(GitleaksAdapter(), make_ctx(tmp_path), runner)

    assert_noise_gone_but_tokens_kept(result)


def test_gitleaks_history_mode_applies_the_same_rule(tmp_path, runner, make_ctx):
    repo = tmp_path / "repo"
    make_ios_repo(repo)
    fx.init_repo(repo)
    fx.commit_all(repo, "add ios lock file and deploy script")
    ctx = make_ctx(repo, gitleaks_mode="git", gitleaks_log_opts="--all")

    result = run_adapter(GitleaksAdapter(), ctx, runner)

    assert_noise_gone_but_tokens_kept(result)
    assert all(f.extra["history_commit"] for f in result.findings)  # still tied to their commit


def test_semgrep_reports_partly_parsed_files_in_its_notes(tmp_path, runner, make_ctx):
    # Semgrep only parses a file that contains something one of the rules is looking for, so
    # each broken file also holds an eval(req.query...) call that the pack's rules search for.
    fx.write(
        tmp_path / "web" / "Page.tsx",
        "export function Page(req) {\n"
        "  eval(req.query.code);\n"
        "  return <ul>{[1, 2].map((i) => <li key={i}>{i}</li>)}</ul>;\n"
        "}\n\n"
        "function broken( {\n"
        "  const x = ;;; @@@ ))\n"
        "}\n",
    )
    fx.write(
        tmp_path / "web" / "legacy.js",
        "export function legacy(req) {\n  eval(req.query.code);\n}\nconst y = ;;; @@@ ))\n",
    )
    fx.write(tmp_path / "web" / "clean.js", "export function ok(req) {\n  return eval(1);\n}\n")
    ctx = make_ctx(tmp_path, rules_dir=RULES, rules_version="test")

    result = run_adapter(SemgrepAdapter(), ctx, runner)

    assert result.status is ScanStatus.OK, (
        result.reason
    )  # the run worked; the note says what it missed
    [note] = [n for n in result.notes if "parsed" in n]
    assert note.startswith("2 file(s) were only partly parsed")
    assert "web/Page.tsx" in note and "web/legacy.js" in note
    assert "clean.js" not in note
    assert "/src" not in note  # repository-relative, not the container path
