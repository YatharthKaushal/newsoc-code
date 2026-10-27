"""Static checks on the clean-room Semgrep rule pack (the sandboxed `semgrep --test` run is in
tests/integration/test_rule_pack_semgrep.py)."""

from __future__ import annotations

import re
import time
from pathlib import Path

import pytest
import yaml

from newsoc_code.scanners.base import read_source_lines
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


# ---- obfuscated-loader family (supply-chain malware hidden in JavaScript files)

LOADER_FAMILY = {
    "newsoc.js.eval-decoded-payload",
    "newsoc.js.hidden-payload-padding",
    "newsoc.js.obfuscated-javascript",
    "newsoc.js.obfuscated-loader",
}
SOURCE_GLOBS = {"*.js", "*.jsx", "*.mjs", "*.cjs", "*.ts", "*.tsx", "*.mts", "*.cts"}


def _all_rules() -> dict[str, dict]:
    return {r["id"]: r for p in YAML_FILES for r in _rules(p)}


def _text_rules() -> list[tuple[Path, dict]]:
    return [(p, r) for p in YAML_FILES for r in _rules(p) if r["languages"] == ["regex"]]


def _pcre_to_python(pattern: str) -> re.Pattern[str]:
    """Python equivalent of a Semgrep ``pattern-regex``. PCRE's ``\\K`` only moves where the
    reported match starts; it does not change whether a line matches, so dropping it is exact
    for the yes/no question these tests ask. PCRE ``\\x{00a0}`` becomes Python ``\\u00a0``."""
    pattern = re.sub(r"\\x\{([0-9a-fA-F]{1,4})\}", lambda m: "\\u" + m.group(1).zfill(4), pattern)
    return re.compile(pattern.replace(r"\K", ""), re.MULTILINE)


def test_the_loader_family_is_in_the_pack():
    assert set(_all_rules()) >= LOADER_FAMILY


def test_blocking_loader_rules_are_graded_like_blocking_rules():
    rules = _all_rules()
    for rid in ("newsoc.js.eval-decoded-payload", "newsoc.js.hidden-payload-padding"):
        meta = rules[rid]["metadata"]
        assert (meta["severity"], meta["confidence"]) == ("critical", "HIGH"), rid
    # obfuscation alone does not say what the code does: it must never block
    warn = rules["newsoc.js.obfuscated-javascript"]
    assert warn["severity"] == "WARNING"
    assert warn["metadata"]["confidence"] == "LOW"
    assert any("CWE-506" in c for c in warn["metadata"]["cwe"])


@pytest.mark.parametrize("path,rule", _text_rules(), ids=[r["id"] for _, r in _text_rules()])
def test_text_level_rules_only_read_javascript_and_typescript(path: Path, rule: dict):
    """A ``regex`` rule applies to every file type unless ``paths.include`` narrows it."""
    assert set(rule["paths"]["include"]) <= SOURCE_GLOBS
    assert rule["paths"]["include"], f"{rule['id']}: a text-level rule needs paths.include"
    assert "exclude" not in rule["paths"], "keep exclusions in the adapter, not in single rules"


_ANNOTATION = re.compile(r"^\s*//\s*(ruleid|ok):\s*(\S+)\s*$")


def _annotated_lines(test_file: Path, rule_id: str) -> list[tuple[str, int, str]]:
    """(kind, 1-based line number, the line the annotation applies to) for one rule."""
    lines = test_file.read_text().split("\n")
    found = []
    for i, line in enumerate(lines[:-1]):
        m = _ANNOTATION.match(line)
        if m and m.group(2) == rule_id:
            found.append((m.group(1), i + 2, lines[i + 1]))
    return found


@pytest.mark.parametrize("path,rule", _text_rules(), ids=[r["id"] for _, r in _text_rules()])
def test_text_level_rules_agree_with_their_fixtures_without_docker(path: Path, rule: dict):
    """The sandboxed ``semgrep --test`` is the authority; this catches a regex edit that breaks
    a fixture (or a Python/PCRE divergence) on machines without Docker."""
    regex = _pcre_to_python(rule["pattern-regex"])
    cases = _annotated_lines(path.with_suffix(".js"), rule["id"])
    assert cases
    for kind, number, text in cases:
        hit = regex.search(text) is not None
        assert hit == (kind == "ruleid"), f"{path.stem}.js:{number} expected {kind}"


def test_the_two_obfuscated_name_rules_share_one_definition():
    """obfuscated-javascript reports exactly the lines obfuscated-loader leaves alone."""
    rules = _all_rules()
    loader = rules["newsoc.js.obfuscated-loader"]["pattern-regex"].strip()
    plain = rules["newsoc.js.obfuscated-javascript"]["pattern-regex"].strip()
    loader_head, loader_names = loader.split(r"\K")
    plain_head, plain_names = plain.split(r"\K")
    assert loader_names == plain_names
    skip_comments = r"(?m)^(?![ \t]*+(?://|\*(?!/)))"
    assert loader_head.startswith(skip_comments + "(?=")
    assert plain_head.startswith(skip_comments + "(?!")
    assert loader_head.removeprefix(skip_comments + "(?=") == plain_head.removeprefix(
        skip_comments + "(?!"
    )


def _layout_of_the_known_loader() -> dict[str, str]:
    """The structure seen in a real injected config file, built from inert pieces."""
    payload = (
        "global.i = 'T0-demo';var __0xaa11b=function(){return 1;};function __0xbb22c(){return 2;}"
        "(function(_0xcc33d){var _0xcc33da=['c2FtcGxl','dGVzdA=='].join('');"
        "var _0xcc33db=atob(_0xcc33da);eval(_0xcc33db);})();"
    )
    return {
        "after_real_code": "module.exports = {\n  presets: [],\n};" + " " * 500 + payload + "\n",
        "own_line": " " * 500 + payload + "\n",
    }


@pytest.mark.parametrize("variant", ["after_real_code", "own_line"])
def test_the_known_layout_is_caught_by_the_padding_and_loader_rules(variant: str):
    rules = _all_rules()
    text = _layout_of_the_known_loader()[variant]
    pad = _pcre_to_python(rules["newsoc.js.hidden-payload-padding"]["pattern-regex"])
    loader = _pcre_to_python(rules["newsoc.js.obfuscated-loader"]["pattern-regex"])
    plain = _pcre_to_python(rules["newsoc.js.obfuscated-javascript"]["pattern-regex"])
    assert pad.search(text)
    assert loader.search(text)
    assert not plain.search(text)


def test_evidence_for_a_padded_line_shows_the_hidden_code(tmp_path: Path):
    """A 200-character snippet of a padded line used to be 200 blanks."""
    (tmp_path / "babel.config.js").write_text(
        "module.exports = {};" + " " * 500 + "global.i = 'T0-demo';\n"
        "    nested();\n" + " " * 48 + "deep();\n"
    )
    first, second, third = read_source_lines(tmp_path, "babel.config.js", 1, 3)
    assert first == "module.exports = {}; [...] global.i = 'T0-demo';"
    assert second == "    nested();"  # normal indentation is untouched
    assert third == " " * 48 + "deep();"


def test_ordinary_whitespace_never_matches_the_padding_rule():
    pad = _pcre_to_python(_all_rules()["newsoc.js.hidden-payload-padding"]["pattern-regex"])
    ordinary = [
        "const a = 1;" + " " * 200 + "// aligned comment that is long enough to look like code\n",
        "const a = 1;" + " " * 300 + "\n",
        " " * 120
        + "return someVeryLongExpression(withArguments, andMoreArguments, andMore, and);\n",
        "const s = '" + " " * 200 + "text that continues for quite a long while after the gap';\n",
        "\n".join("    " * depth + "x();" for depth in range(30)) + "\n",
    ]
    assert [t for t in ordinary if pad.search(t)] == []


def test_text_level_loader_rules_do_not_backtrack_catastrophically():
    """Hostile files are scanned: every pattern must stay linear on whitespace, repeated
    separators and long runs of near-matches (Semgrep itself stops a rule after 30 s)."""
    rules = _all_rules()
    hostile = [
        " " * 900_000 + "\n",
        (";" + " " * 120 + "\n") * 7_000,
        (";" + " " * 120 + "x") * 7_000 + "\n",
        "_0x1234 " * 100_000 + "\n",
        ("_0x1234" + "a" * 201) * 4_000 + "\n",
        "eval( " * 150_000 + "\n",
        "var a=eval(1);\n" * 60_000,
    ]
    for rid in LOADER_FAMILY:
        if "pattern-regex" not in rules[rid]:
            continue
        regex = _pcre_to_python(rules[rid]["pattern-regex"])
        started = time.perf_counter()
        for text in hostile:
            regex.search(text)
        assert time.perf_counter() - started < 20, rid


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
