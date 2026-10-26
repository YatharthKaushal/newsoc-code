"""Gitleaks' entropy rule must not report dependency checksums, but specific rules still must.

The reports are built here from fragments instead of being committed as JSON: a committed
"<name>: <40 hex digits>" line is exactly what the entropy rule flags, and this repository is
scanned by a secret scanner too.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import builders as fx
import pytest

from newsoc_code.findings.schema import ScanStatus
from newsoc_code.scanners.gitleaks import (
    CHECKSUM_MANIFEST_PATTERNS,
    GitleaksAdapter,
    is_checksum_manifest,
)
from tests.conftest import run_output


def checksum(name: str) -> str:
    """A 40-digit hex string like the SHA-1 values in a Podfile.lock, computed at test time."""
    return hashlib.sha1(name.encode()).hexdigest()


def leak(
    rule: str,
    file: str,
    secret: str,
    *,
    line: int = 3,
    match: str | None = None,
    commit: str = "",
) -> dict[str, Any]:
    return {
        "RuleID": rule,
        "Description": f"Detected {rule}.",
        "StartLine": line,
        "EndLine": line,
        "Match": match if match is not None else f"key: {secret}",
        "Secret": secret,
        "File": file,
        "Commit": commit,
        "Entropy": 3.9,
    }


def parse(ctx, leaks: list[dict[str, Any]], exit_code: int = 1):
    (ctx.out_dir / "gitleaks.json").write_text(json.dumps(leaks), encoding="utf-8")
    return GitleaksAdapter().parse(ctx, run_output(exit_code))


# ---- the reported case -------------------------------------------------------------------------


def test_podfile_lock_checksums_are_not_reported_but_other_files_still_are(tmp_path, make_ctx):
    pods = ["AppAuth", "GTMAppAuth", "React-cxxstableapi"]
    leaks = [
        leak(
            "generic-api-key",
            "/src/ios/Podfile.lock",
            checksum(pod),
            line=2245 + i,
            match=f"{pod}: {checksum(pod)}",
        )
        for i, pod in enumerate(pods)
    ]
    leaks.append(leak("generic-api-key", "/src/babel.config.js", fx.AWS_SECRET))

    result = parse(make_ctx(tmp_path), leaks)

    assert result.status is ScanStatus.OK
    assert [(f.rule_id, f.path) for f in result.findings] == [
        ("generic-api-key", "babel.config.js")
    ]
    [note] = result.notes
    assert "3 generic-api-key match(es)" in note and "ios/Podfile.lock" in note
    dumped = json.dumps(result.model_dump(mode="json"))
    assert not any(checksum(p) in dumped for p in pods)


def test_when_only_checksums_were_hit_the_scan_is_verified_not_failed(tmp_path, make_ctx):
    leaks = [leak("generic-api-key", "/src/ios/Podfile.lock", checksum("AppAuth"))]

    result = parse(make_ctx(tmp_path), leaks, exit_code=1)  # gitleaks exits 1 when it finds leaks

    assert result.status is ScanStatus.OK
    assert result.findings == []
    assert result.assessment().value == "Verified"
    assert len(result.notes) == 1  # the suppression stays visible even when nothing is left


def test_a_scan_without_suppressions_adds_no_note(tmp_path, make_ctx, place_report):
    ctx = make_ctx(tmp_path)
    place_report(ctx, "gitleaks/two-secrets-one-repeated.json", "gitleaks.json")

    result = GitleaksAdapter().parse(ctx, run_output(1))

    assert len(result.findings) == 2
    assert result.notes == []


# ---- which files count as manifests ------------------------------------------------------------

MANIFESTS = [
    "ios/Podfile.lock",
    "yarn.lock",
    "web/Cargo.lock",
    "Gemfile.lock",
    "poetry.lock",
    "composer.lock",
    "flake.lock",
    "uv.lock",
    "package-lock.json",
    "apps/web/package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "go.sum",
    "go.work.sum",
    "Package.resolved",
    "gradle.lockfile",
    "packages.lock.json",
    "infra/.terraform.lock.hcl",
    "IOS/PODFILE.LOCK",  # names are matched case-insensitively
    "/src/ios/Podfile.lock",  # the container prefix is stripped first
]
NOT_MANIFESTS = [
    "src/config.js",
    "package.json",
    "unlock.txt",
    "lock.js",
    "summary.txt",
    "requirements.txt",
    "notes.sum.txt",
    "vendor.lock/config.js",  # a directory called *.lock does not make its files manifests
    "package-lock.json.js",
    ".env",
]


@pytest.mark.parametrize("path", MANIFESTS)
def test_manifest_names_are_recognised(path):
    assert is_checksum_manifest(path)


@pytest.mark.parametrize("path", NOT_MANIFESTS)
def test_ordinary_files_are_not_manifests(path):
    assert not is_checksum_manifest(path)


def test_the_pattern_list_is_a_plain_tuple_of_lowercase_patterns():
    # case-insensitive matching lower-cases the file name only, so patterns must be lower case
    assert all(p == p.lower() for p in CHECKSUM_MANIFEST_PATTERNS)


@pytest.mark.parametrize("path", MANIFESTS)
def test_generic_hits_in_every_manifest_kind_are_dropped(tmp_path, make_ctx, path):
    leaks = [leak("generic-api-key", path, checksum(path))]
    result = parse(make_ctx(tmp_path), leaks)
    assert result.findings == []
    assert len(result.notes) == 1


@pytest.mark.parametrize("path", NOT_MANIFESTS)
def test_generic_hits_elsewhere_are_kept(tmp_path, make_ctx, path):
    leaks = [leak("generic-api-key", path, fx.AWS_SECRET)]
    result = parse(make_ctx(tmp_path), leaks)
    assert len(result.findings) == 1
    assert result.notes == []


# ---- specific rules are never suppressed -------------------------------------------------------


@pytest.mark.parametrize(
    ("rule", "secret"),
    [
        ("github-pat", fx.GITHUB_TOKEN),
        ("aws-access-token", fx.AWS_KEY),
        ("private-key", "-----BEGIN-" + "PRIVATE-KEY-BODY"),
        ("some-future-specific-rule", fx.AWS_SECRET),
    ],
)
@pytest.mark.parametrize("path", ["ios/Podfile.lock", "yarn.lock", "go.sum", "package-lock.json"])
def test_a_specific_rule_inside_a_manifest_is_still_reported(
    tmp_path, make_ctx, rule, secret, path
):
    leaks = [
        leak(rule, f"/src/{path}", secret),
        leak("generic-api-key", f"/src/{path}", checksum(path)),
    ]

    result = parse(make_ctx(tmp_path), leaks)

    assert [(f.rule_id, f.path) for f in result.findings] == [(rule, path)]
    assert len(result.notes) == 1  # only the entropy hit was dropped, and that is recorded
    assert secret not in json.dumps(result.model_dump(mode="json"))


def test_a_generic_secret_that_also_sits_in_a_manifest_is_still_reported_from_source(
    tmp_path, make_ctx
):
    shared = fx.AWS_SECRET
    leaks = [
        leak("generic-api-key", "/src/ios/Podfile.lock", shared, line=5),
        leak("generic-api-key", "/src/src/config.js", shared, line=9),
    ]

    result = parse(make_ctx(tmp_path), leaks)

    [finding] = result.findings
    assert finding.path == "src/config.js" and finding.start_line == 9
    assert finding.extra["other_locations"] == []  # the manifest location is not listed as a leak


# ---- git history mode --------------------------------------------------------------------------


def test_history_records_are_filtered_by_the_path_they_had_in_that_commit(tmp_path, make_ctx):
    c1, c2, c3 = "1" * 40, "2" * 40, "3" * 40
    leaks = [
        # history paths have no /src prefix and carry the commit that introduced the line
        leak("generic-api-key", "ios/Podfile.lock", checksum("a"), commit=c1),
        leak("generic-api-key", "ios/Podfile.lock", checksum("b"), commit=c2),
        leak("github-pat", "ios/Podfile.lock", fx.GITHUB_TOKEN, commit=c2),
        leak("generic-api-key", "src/config.js", fx.AWS_SECRET, commit=c3),
    ]
    ctx = make_ctx(tmp_path, gitleaks_mode="git", gitleaks_log_opts="--all")

    result = parse(ctx, leaks)

    by_rule = {f.rule_id: f for f in result.findings}
    assert set(by_rule) == {"github-pat", "generic-api-key"}
    assert by_rule["github-pat"].extra["history_commit"] == c2  # still attributed to its commit
    assert by_rule["github-pat"].commit == c2
    assert by_rule["generic-api-key"].path == "src/config.js"
    assert by_rule["generic-api-key"].extra["history_commit"] == c3
    [note] = result.notes
    assert "2 generic-api-key match(es)" in note


def test_a_secret_deleted_from_source_stays_reported_even_if_a_lock_file_repeats_it(
    tmp_path, make_ctx
):
    old, new = "a" * 40, "b" * 40
    leaks = [
        leak("generic-api-key", "ios/Podfile.lock", fx.AWS_SECRET, commit=new),
        leak("generic-api-key", "src/config.js", fx.AWS_SECRET, commit=old, line=4),
    ]

    result = parse(make_ctx(tmp_path, gitleaks_mode="git"), leaks)

    [finding] = result.findings
    assert (finding.path, finding.extra["history_commit"]) == ("src/config.js", old)


def test_the_suppression_note_lists_a_few_files_and_counts_the_rest(tmp_path, make_ctx):
    paths = [f"mod{i}/Cargo.lock" for i in range(6)]
    leaks = [leak("generic-api-key", p, checksum(p)) for p in paths]

    result = parse(make_ctx(tmp_path), leaks)

    [note] = result.notes
    assert "6 generic-api-key match(es)" in note
    assert "mod0/Cargo.lock, mod1/Cargo.lock, mod2/Cargo.lock (+3 more)" in note
    assert "mod5/Cargo.lock" not in note
