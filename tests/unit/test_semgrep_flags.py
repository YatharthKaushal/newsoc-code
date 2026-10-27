"""Semgrep command-line flags that protect the gate."""

from __future__ import annotations

from pathlib import Path

from newsoc_code.scanners.semgrep import SemgrepAdapter

RULES = Path(__file__).parents[2] / "rules" / "semgrep"


def test_a_pull_request_cannot_silence_a_rule_with_a_nosemgrep_comment(tmp_path, make_ctx):
    """Measured in the sandbox: without this flag a trailing ``// nosemgrep`` hid every finding
    on a hidden-payload line. Waivers belong in .secpolicy.yml (read from the base branch)."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x = 1\n")
    argv = list(SemgrepAdapter().spec(make_ctx(src, rules_dir=RULES)).argv)
    assert "--disable-nosem" in argv
