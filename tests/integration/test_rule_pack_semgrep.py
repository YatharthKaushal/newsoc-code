"""Run `semgrep --test` over the whole rule pack inside the sandbox."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.docker

SCRIPT = Path(__file__).parents[2] / "scripts" / "test_rules.sh"


def test_every_rule_passes_its_annotated_tests():
    done = subprocess.run([str(SCRIPT)], capture_output=True, text=True, check=False, timeout=900)
    output = done.stdout + done.stderr
    assert done.returncode == 0, output[-3000:]
    assert "All tests passed" in output, output[-3000:]
