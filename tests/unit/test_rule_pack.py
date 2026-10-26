"""Static checks on the clean-room Semgrep rule pack (the sandboxed `semgrep --test` run is in
tests/integration/test_rule_pack_semgrep.py)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from newsoc_code.scanners.semgrep import SemgrepAdapter
from tests.conftest import GOLDEN  # noqa: F401  (keeps the package import path stable)

RULES = Path(__file__).parents[2] / "rules" / "semgrep"
SEVERITIES = {"critical", "high", "medium", "low"}
CONFIDENCES = {"HIGH", "MEDIUM", "LOW"}
LEVELS = {"ERROR", "WARNING", "INFO"}
YAML_FILES = sorted(RULES.rglob("*.yaml"))


def _rules(path: Path) -> list[dict]:
    return yaml.safe_load(path.read_text())["rules"]


def test_the_pack_is_big_enough():
    total = sum(len(_rules(p)) for p in YAML_FILES)
    assert total >= 25, f"only {total} rules; the MVP plan calls for about 25 to start"


@pytest.mark.parametrize("path", YAML_FILES, ids=[p.stem for p in YAML_FILES])
def test_every_rule_is_namespaced_documented_and_graded(path: Path):
    lang_dir = path.parent.name
    for rule in _rules(path):
        rid = rule["id"]
        assert rid.startswith(f"newsoc.{lang_dir}."), (
            f"{rid}: id must start with newsoc.{lang_dir}."
        )
        assert rid == f"newsoc.{lang_dir}.{path.stem}", f"{rid}: id must match the file name"
        assert len(" ".join(rule["message"].split())) >= 40, (
            f"{rid}: message is too short to be useful"
        )
        assert rule["severity"] in LEVELS
        meta = rule["metadata"]
        assert meta["severity"] in SEVERITIES, f"{rid}: metadata.severity"
        assert meta["confidence"] in CONFIDENCES, f"{rid}: metadata.confidence"
        assert meta["cwe"] and all(re.match(r"CWE-\d+", c) for c in meta["cwe"]), (
            f"{rid}: metadata.cwe"
        )
        assert meta["owasp"], f"{rid}: metadata.owasp"
        assert "clean-room" in meta["provenance"], f"{rid}: provenance note is required"


@pytest.mark.parametrize("path", YAML_FILES, ids=[p.stem for p in YAML_FILES])
def test_low_confidence_rules_only_warn(path: Path):
    """LOW confidence never blocks in the policy engine; keep the Semgrep level consistent."""
    for rule in _rules(path):
        if rule["metadata"]["confidence"] == "LOW":
            assert rule["severity"] == "WARNING", (
                f"{rule['id']}: LOW confidence rules must be WARNING"
            )


@pytest.mark.parametrize("path", YAML_FILES, ids=[p.stem for p in YAML_FILES])
def test_every_rule_has_positive_and_negative_tests(path: Path):
    tests = [p for p in path.parent.glob(f"{path.stem}.*") if p.suffix != ".yaml"]
    assert tests, f"{path.name}: no test file next to the rule"
    text = "\n".join(t.read_text() for t in tests)
    for rule in _rules(path):
        positives = len(re.findall(rf"ruleid:\s*{re.escape(rule['id'])}\b", text))
        negatives = len(re.findall(rf"\bok:\s*{re.escape(rule['id'])}\b", text))
        assert positives >= 2, f"{rule['id']}: needs at least 2 positive cases (has {positives})"
        assert negatives >= 2, (
            f"{rule['id']}: needs at least 2 near-miss negatives (has {negatives})"
        )


def test_rule_ids_are_unique():
    ids = [r["id"] for p in YAML_FILES for r in _rules(p)]
    assert len(ids) == len(set(ids))


# ---- the registry must never be used: the Semgrep Rules License forbids it in a product we sell


def test_semgrep_adapter_only_ever_uses_the_local_rule_pack(tmp_path, make_ctx):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x = 1\n")
    ctx = make_ctx(src, rules_dir=RULES)
    argv = list(SemgrepAdapter().spec(ctx).argv)

    configs = [argv[i + 1] for i, a in enumerate(argv) if a in ("--config", "-c", "-f")]
    assert configs == ["/rules"], f"semgrep may only read the mounted rule pack, got {configs}"
    joined = " ".join(argv)
    for forbidden in ("auto", "p/", "r/", "http://", "https://", "semgrep.dev", "--pro"):
        assert forbidden not in argv and forbidden not in joined.replace("/rules", ""), forbidden


def test_no_source_file_references_registry_rule_packs():
    root = Path(__file__).parents[2]
    offenders = []
    for path in (
        list((root / "src").rglob("*.py"))
        + list(p for p in (root / "scripts").glob("*") if p.is_file())
        + [root / "docker" / "scanners.Dockerfile"]
    ):
        text = path.read_text(errors="ignore")
        if re.search(r"--config[= ]+(auto|p/|r/|https?://)", text) or "semgrep.dev/c/" in text:
            offenders.append(path.name)
    assert offenders == []
