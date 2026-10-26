"""The adapters' pinned versions must match the image they run in."""

from __future__ import annotations

import re
from pathlib import Path

from newsoc_code.scanners.checkov import CheckovAdapter
from newsoc_code.scanners.gitleaks import GitleaksAdapter
from newsoc_code.scanners.osv import OsvAdapter
from newsoc_code.scanners.semgrep import SemgrepAdapter

DOCKERFILE = Path(__file__).parents[2] / "docker" / "scanners.Dockerfile"


def _arg(name: str) -> str:
    match = re.search(rf"^ARG {name}=(\S+)$", DOCKERFILE.read_text(), re.MULTILINE)
    assert match, f"{name} not found in {DOCKERFILE}"
    return match.group(1)


def test_adapter_versions_match_the_dockerfile():
    assert SemgrepAdapter.pinned_version == _arg("SEMGREP_VERSION")
    assert CheckovAdapter.pinned_version == _arg("CHECKOV_VERSION")
    assert OsvAdapter.pinned_version == _arg("OSV_SCANNER_VERSION")
    assert GitleaksAdapter.pinned_version == _arg("GITLEAKS_VERSION")


def test_every_download_is_checksummed():
    text = DOCKERFILE.read_text()
    assert "sha256sum -c" in text
    assert re.search(r"^ARG OSV_SCANNER_SHA256=[0-9a-f]{64}$", text, re.MULTILINE)
    assert re.search(r"^ARG GITLEAKS_SHA256=[0-9a-f]{64}$", text, re.MULTILINE)
