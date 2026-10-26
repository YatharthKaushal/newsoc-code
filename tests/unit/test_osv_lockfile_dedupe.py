"""One vulnerable dependency is one finding, however many lockfiles of a directory list it.

The OSV reports below are built by hand from invented packages and advisory ids; the shape follows
the real report (see tests/golden/osv/npm-and-pypi.json), nothing is copied from a repository.
"""

from __future__ import annotations

import itertools
import json
from dataclasses import dataclass
from datetime import date
from typing import Any

import pytest

from newsoc_code.findings import baseline as baselines
from newsoc_code.findings.fingerprint import project_dir, sca_fingerprint
from newsoc_code.findings.schema import Confidence, ScanResult, ScanStatus, Severity
from newsoc_code.policy.engine import Conclusion, Outcome, evaluate
from newsoc_code.policy.loader import load_policy
from newsoc_code.scanners.osv import LOCKFILE_PREFERENCE, OsvAdapter
from tests.conftest import run_output

TODAY = date(2026, 10, 26)
ENFORCE = "mode: enforce\n"


@dataclass(frozen=True)
class Adv:
    cve: str
    ghsa: str
    score: str = "7.5"
    fixed: str = "2.0.0"


ADV1 = Adv("CVE-2099-0001", "GHSA-test-0001-aaaa")
ADV2 = Adv("CVE-2099-0002", "GHSA-test-0002-bbbb", score="9.8", fixed="3.1.0")


def pkg(name: str, version: str, *advisories: Adv, ecosystem: str = "npm") -> dict[str, Any]:
    return {
        "package": {"name": name, "version": version, "ecosystem": ecosystem},
        "groups": [
            {"ids": [a.ghsa], "aliases": [a.cve, a.ghsa], "max_severity": a.score}
            for a in advisories
        ],
        "vulnerabilities": [
            {
                "id": a.ghsa,
                "aliases": [a.cve],
                "summary": f"Synthetic flaw {a.cve}",
                "database_specific": {"cwe_ids": ["CWE-1333"], "severity": "HIGH"},
                "affected": [
                    {
                        "package": {"name": name, "ecosystem": ecosystem},
                        "ranges": [
                            {
                                "type": "SEMVER",
                                "events": [{"introduced": "0"}, {"fixed": a.fixed}],
                            }
                        ],
                    }
                ],
            }
            for a in advisories
        ],
    }


def source(path: str, *packages: dict[str, Any], kind: str = "lockfile") -> dict[str, Any]:
    return {"source": {"path": f"/src/{path}", "type": kind}, "packages": list(packages)}


@pytest.fixture
def scan(tmp_path, make_ctx):
    """Parse a hand-built OSV report (``results`` entries) into a ScanResult."""

    def _scan(*sources: dict[str, Any], files: dict[str, str] | None = None) -> ScanResult:
        for rel, text in (files or {}).items():
            (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
            (tmp_path / rel).write_text(text, encoding="utf-8")
        ctx = make_ctx(tmp_path)
        (ctx.out_dir / "osv.json").write_text(json.dumps({"results": list(sources)}))
        result = OsvAdapter().parse(ctx, run_output(1))
        assert result.status is ScanStatus.OK, result.reason
        return result

    return _scan


def lock_sources(paths: list[str], *packages: dict[str, Any]) -> list[dict[str, Any]]:
    return [source(path, *packages) for path in paths]


# ---- the duplicate this change removes -------------------------------------------------------


def test_the_same_dependency_in_two_lockfiles_is_one_finding(scan):
    widget = pkg("example-widget", "1.0.0", ADV1)

    result = scan(*lock_sources(["package-lock.json", "yarn.lock"], widget))

    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.path == "package-lock.json"  # the preferred lockfile carries the finding
    assert f.rule_id == "CVE-2099-0001"
    assert f.extra["also_in"] == ["yarn.lock"]
    assert f.extra["package"] == "example-widget" and f.extra["version"] == "1.0.0"
    assert "also in yarn.lock" in f.message  # visible in the PR comment and the annotation
    assert any("also in: yarn.lock" in line for line in f.evidence)  # and in the details
    assert any("merged" in n for n in result.notes)  # the scan says it merged something


def test_three_lockfiles_name_both_others_sorted(scan):
    widget = pkg("example-widget", "1.0.0", ADV1)

    result = scan(*lock_sources(["yarn.lock", "pnpm-lock.yaml", "package-lock.json"], widget))

    (f,) = result.findings
    assert f.path == "package-lock.json"
    assert f.extra["also_in"] == ["pnpm-lock.yaml", "yarn.lock"]  # sorted, primary excluded
    assert "also in pnpm-lock.yaml, yarn.lock" in f.message
    assert any("also in: pnpm-lock.yaml, yarn.lock" in line for line in f.evidence)


def test_a_finding_that_exists_in_one_lockfile_only_is_unchanged(scan):
    result = scan(source("yarn.lock", pkg("example-widget", "1.0.0", ADV1)))

    (f,) = result.findings
    assert f.path == "yarn.lock"
    assert f.extra["also_in"] == []
    assert "also in" not in f.message
    assert not any("also in" in line for line in f.evidence)
    assert not any("merged" in n for n in result.notes)


def test_every_package_of_a_doubled_report_is_halved(scan):
    """The shape of the real-world case: two lockfiles in a directory, each listing everything."""
    packages = [pkg(f"example-pkg-{i}", "1.0.0", ADV1, ADV2) for i in range(20)]

    doubled = scan(*lock_sources(["package-lock.json", "yarn.lock"], *packages))
    single = scan(source("package-lock.json", *packages))

    assert len(doubled.findings) == len(single.findings) == 40  # 20 packages x 2 advisories
    assert [f.fingerprint for f in doubled.findings] == [f.fingerprint for f in single.findings]
    assert all(f.extra["also_in"] == ["yarn.lock"] for f in doubled.findings)


# ---- which lockfile is primary ----------------------------------------------------------------

PREFERENCE_CASES = [
    # npm: shrinkwrap, package-lock.json, yarn.lock, pnpm-lock.yaml
    (["pnpm-lock.yaml", "yarn.lock", "package-lock.json", "npm-shrinkwrap.json"], "npm"),
    # PyPI: tool lockfiles before requirements.txt
    (["requirements.txt", "Pipfile.lock", "pdm.lock", "uv.lock", "poetry.lock"], "PyPI"),
]


@pytest.mark.parametrize(("paths", "ecosystem"), PREFERENCE_CASES)
def test_primary_follows_the_documented_preference_whatever_the_report_order(
    scan, paths, ecosystem
):
    dependency = pkg("example-widget", "1.0.0", ADV1, ecosystem=ecosystem)
    expected_order = sorted(paths, key=lambda p: LOCKFILE_PREFERENCE.index(p.lower()))
    reference: list[dict[str, Any]] | None = None

    for ordering in itertools.permutations(paths):
        result = scan(*lock_sources(list(ordering), dependency))
        (f,) = result.findings
        assert f.path == expected_order[0], ordering
        assert f.extra["also_in"] == sorted(expected_order[1:]), ordering
        dumped = [x.model_dump(mode="json") for x in result.findings]
        reference = reference or dumped
        assert dumped == reference, ordering  # byte-for-byte the same finding in every order


def test_the_preference_lists_every_lockfile_the_adapter_accepts():
    from newsoc_code.scanners.osv import LOCKFILES

    # A lockfile the scanner is applicable to but missing here would rank last by accident.
    assert {name.lower() for name in LOCKFILES} <= {name.lower() for name in LOCKFILE_PREFERENCE}


def test_unknown_lockfile_names_rank_after_known_ones_then_by_path(scan):
    dependency = pkg("example-widget", "1.0.0", ADV1, ecosystem="PyPI")

    result = scan(
        *lock_sources(
            ["b-reqs.txt", "requirements-dev.txt", "a-reqs.txt", "requirements.txt"], dependency
        )
    )

    (f,) = result.findings
    assert f.path == "requirements.txt"  # known beats unknown, although "-" sorts before "."
    assert f.extra["also_in"] == ["a-reqs.txt", "b-reqs.txt", "requirements-dev.txt"]

    only_unknown = scan(*lock_sources(["b-reqs.txt", "a-reqs.txt"], dependency))
    assert only_unknown.findings[0].path == "a-reqs.txt"  # ties break on the path


def test_a_python_package_is_matched_across_lockfiles_despite_naming_differences(scan):
    result = scan(
        source("requirements.txt", pkg("Acme_Yaml.Tools", "1.0", ADV1, ecosystem="PyPI")),
        source("poetry.lock", pkg("acme-yaml-tools", "1.0", ADV1, ecosystem="PyPI")),
    )

    (f,) = result.findings
    assert f.path == "poetry.lock"
    assert f.extra["also_in"] == ["requirements.txt"]


# ---- what must stay separate ------------------------------------------------------------------


def test_different_versions_of_one_package_stay_separate_findings(scan):
    result = scan(
        source("package-lock.json", pkg("example-widget", "1.0.0", ADV1)),
        source("yarn.lock", pkg("example-widget", "1.1.0", ADV1)),
    )

    assert sorted((f.path, f.extra["version"]) for f in result.findings) == [
        ("package-lock.json", "1.0.0"),
        ("yarn.lock", "1.1.0"),
    ]
    assert all(f.extra["also_in"] == [] for f in result.findings)
    # The fingerprint deliberately ignores the version (a bump that leaves the advisory unfixed
    # is not new), so these two findings share one. Each is still reported on its own.
    assert len({f.fingerprint for f in result.findings}) == 1


def test_a_version_listed_twice_in_one_lockfile_and_once_in_another_is_still_one_finding(scan):
    widget = pkg("example-widget", "1.0.0", ADV1)

    result = scan(source("package-lock.json", widget, widget), source("yarn.lock", widget))

    (f,) = result.findings
    assert f.extra["also_in"] == ["yarn.lock"]


def test_a_duplicate_inside_one_lockfile_is_merged_without_an_also_in(scan):
    widget = pkg("example-widget", "1.0.0", ADV1)

    result = scan(source("package-lock.json", widget, widget))

    (f,) = result.findings
    assert f.extra["also_in"] == []
    assert "also in" not in f.message


def test_the_same_advisory_in_different_directories_stays_separate(scan):
    widget = pkg("example-widget", "1.0.0", ADV1)

    result = scan(
        source("package-lock.json", widget),
        source("apps/web/package-lock.json", widget),
        source("apps/web/yarn.lock", widget),
        source("apps/api/yarn.lock", widget),
    )

    by_path = {f.path: f for f in result.findings}
    assert sorted(by_path) == [
        "apps/api/yarn.lock",
        "apps/web/package-lock.json",
        "package-lock.json",
    ]
    assert by_path["package-lock.json"].extra["also_in"] == []
    assert by_path["apps/web/package-lock.json"].extra["also_in"] == ["apps/web/yarn.lock"]
    assert by_path["apps/api/yarn.lock"].extra["also_in"] == []
    assert len({f.fingerprint for f in result.findings}) == 3
    assert by_path["apps/web/package-lock.json"].extra["project_dir"] == "apps/web"
    assert by_path["package-lock.json"].extra["project_dir"] == "."


def test_a_directory_and_its_parent_never_merge(scan):
    widget = pkg("example-widget", "1.0.0", ADV1)

    result = scan(source("web/package-lock.json", widget), source("web/sub/yarn.lock", widget))

    assert len(result.findings) == 2


def test_the_same_package_name_in_other_ecosystems_stays_separate(scan):
    result = scan(
        source("package-lock.json", pkg("example-widget", "1.0.0", ADV1, ecosystem="npm")),
        source("requirements.txt", pkg("example-widget", "1.0.0", ADV1, ecosystem="PyPI")),
    )

    assert sorted(f.extra["ecosystem"] for f in result.findings) == ["PyPI", "npm"]
    assert len({f.fingerprint for f in result.findings}) == 2
    assert all(f.extra["also_in"] == [] for f in result.findings)


def test_two_advisories_on_one_package_stay_two_findings(scan):
    widget = pkg("example-widget", "1.0.0", ADV1, ADV2)

    result = scan(*lock_sources(["package-lock.json", "yarn.lock"], widget))

    assert sorted(f.rule_id for f in result.findings) == ["CVE-2099-0001", "CVE-2099-0002"]
    assert all(f.extra["also_in"] == ["yarn.lock"] for f in result.findings)
    assert len({f.fingerprint for f in result.findings}) == 2


def test_merged_finding_keeps_the_strongest_confidence_and_all_ids(scan):
    widget = pkg("example-widget", "1.0.0", ADV1)

    result = scan(
        source("package-lock.json", widget, kind="sbom"),  # preferred, but not an exact lockfile
        source("yarn.lock", widget),
    )

    (f,) = result.findings
    assert f.path == "package-lock.json"
    assert f.confidence is Confidence.HIGH  # one of the sources gives the exact version
    assert f.severity is Severity.HIGH
    assert set(f.vuln_ids) == {ADV1.cve, ADV1.ghsa}
    assert f.cwe == ("CWE-1333",)


# ---- the fingerprint --------------------------------------------------------------------------


def test_fingerprint_is_built_from_the_project_directory_not_the_lockfile(scan):
    widget = pkg("example-widget", "1.0.0", ADV1)
    expected = sca_fingerprint("npm", "example-widget", "", "CVE-2099-0001")

    both = scan(*lock_sources(["package-lock.json", "yarn.lock"], widget))
    npm_only = scan(source("package-lock.json", widget))
    yarn_only = scan(source("yarn.lock", widget))
    pnpm_only = scan(source("pnpm-lock.yaml", widget))

    for result in (both, npm_only, yarn_only, pnpm_only):
        assert [f.fingerprint for f in result.findings] == [expected]


def test_fingerprint_in_a_subdirectory_is_the_same_for_every_lockfile_there(scan):
    widget = pkg("example-widget", "1.0.0", ADV1)

    a = scan(source("apps/web/package-lock.json", widget))
    b = scan(source("apps/web/yarn.lock", widget))

    assert a.findings[0].fingerprint == b.findings[0].fingerprint
    assert a.findings[0].fingerprint == sca_fingerprint(
        "npm", "example-widget", "apps/web", "CVE-2099-0001"
    )
    assert a.findings[0].fingerprint != sca_fingerprint(
        "npm", "example-widget", "", "CVE-2099-0001"
    )


def test_moving_the_package_within_the_lockfile_changes_the_line_not_the_fingerprint(scan):
    widget = pkg("example-widget", "1.0.0", ADV1)
    entry = '    "node_modules/example-widget": {}\n'
    before = scan(
        source("package-lock.json", widget),
        files={"package-lock.json": '{\n  "packages": {\n' + entry + "  }\n}\n"},
    )
    after = scan(
        source("package-lock.json", widget),
        files={
            "package-lock.json": '{\n  "name": "x",\n  "version": "1",\n  "packages": {\n'
            + entry
            + "  }\n}\n"
        },
    )

    assert before.findings[0].start_line == 3
    assert after.findings[0].start_line == 5
    assert before.findings[0].fingerprint == after.findings[0].fingerprint


def test_the_line_comes_from_the_primary_lockfile(scan):
    widget = pkg("example-widget", "1.0.0", ADV1)

    result = scan(
        *lock_sources(["yarn.lock", "package-lock.json"], widget),
        files={
            "yarn.lock": "# a\n# b\n# c\n# d\nexample-widget@1.0.0:\n",
            "package-lock.json": '{\n  "node_modules/example-widget": {}\n}\n',
        },
    )

    (f,) = result.findings
    assert (f.path, f.start_line) == ("package-lock.json", 2)


def test_project_dir_helper():
    assert project_dir("yarn.lock") == ""
    assert project_dir("./yarn.lock") == ""
    assert project_dir("apps/web/yarn.lock") == "apps/web"
    assert project_dir("apps\\web\\yarn.lock") == "apps/web"
    assert project_dir("/apps/web/yarn.lock") == "apps/web"


# ---- baselines and the policy engine ----------------------------------------------------------


def gate(head: ScanResult, baseline: frozenset[str] | None, *, policy: str = ENFORCE):
    return evaluate(load_policy(policy, TODAY), [head], baseline, TODAY)


@pytest.mark.parametrize(
    ("base_files", "head_files"),
    [
        (["package-lock.json", "yarn.lock"], ["package-lock.json"]),  # yarn.lock deleted
        (["package-lock.json", "yarn.lock"], ["yarn.lock"]),  # package-lock.json deleted
        (["yarn.lock"], ["package-lock.json", "yarn.lock"]),  # package-lock.json added
        (["package-lock.json"], ["yarn.lock", "pnpm-lock.yaml"]),  # replaced by two others
        (["package-lock.json", "yarn.lock"], ["package-lock.json", "yarn.lock"]),
    ],
)
def test_a_baseline_survives_adding_or_removing_a_duplicate_lockfile(
    scan, tmp_path, base_files, head_files
):
    widget = pkg("example-widget", "1.0.0", ADV1, ADV2)
    base = scan(*lock_sources(base_files, widget))
    saved = tmp_path / "baseline.json"
    baselines.save(saved, baselines.from_results([base]))  # the cached baseline, as stored
    baseline = baselines.load(saved)

    head = scan(*lock_sources(head_files, widget))
    outcome = gate(head, baseline)

    assert len(head.findings) == 2
    assert {d.outcome for d in outcome.decisions} == {Outcome.BASELINED}
    assert outcome.conclusion is Conclusion.SUCCESS


def test_a_new_advisory_on_a_baselined_package_is_still_new(scan):
    base = scan(
        *lock_sources(["package-lock.json", "yarn.lock"], pkg("example-widget", "1.0.0", ADV1))
    )
    head = scan(source("package-lock.json", pkg("example-widget", "1.0.0", ADV1, ADV2)))

    outcome = gate(head, baselines.from_results([base]))

    by_rule = {d.finding.rule_id: d.outcome for d in outcome.decisions}
    assert by_rule == {"CVE-2099-0001": Outcome.BASELINED, "CVE-2099-0002": Outcome.BLOCKED}
    assert outcome.conclusion is Conclusion.FAILURE


def test_the_same_advisory_in_a_new_directory_is_new_even_if_the_root_is_baselined(scan):
    widget = pkg("example-widget", "1.0.0", ADV1)
    base = scan(*lock_sources(["package-lock.json", "yarn.lock"], widget))
    head = scan(
        *lock_sources(["package-lock.json", "yarn.lock"], widget),
        *lock_sources(["apps/web/package-lock.json", "apps/web/yarn.lock"], widget),
    )

    outcome = gate(head, baselines.from_results([base]))

    by_path = {d.finding.path: d.outcome for d in outcome.decisions}
    assert by_path == {
        "package-lock.json": Outcome.BASELINED,
        "apps/web/package-lock.json": Outcome.BLOCKED,
    }


def test_a_new_package_is_new_and_blocks(scan):
    base = scan(
        *lock_sources(["package-lock.json", "yarn.lock"], pkg("example-widget", "1.0.0", ADV1))
    )
    head = scan(
        *lock_sources(["package-lock.json", "yarn.lock"], pkg("sample-parser", "1.0.0", ADV1))
    )

    outcome = gate(head, baselines.from_results([base]))

    assert [d.outcome for d in outcome.decisions] == [Outcome.BLOCKED]


def test_without_a_baseline_the_duplicate_no_longer_doubles_the_blocking_count(scan):
    widget = pkg("example-widget", "1.0.0", ADV1)
    head = scan(*lock_sources(["package-lock.json", "yarn.lock"], widget))

    outcome = gate(head, None)

    assert outcome.title == "1 blocking finding(s)"  # it used to say 2


def test_a_waiver_on_the_primary_lockfile_waives_the_merged_finding(scan):
    widget = pkg("example-widget", "1.0.0", ADV1)
    head = scan(*lock_sources(["package-lock.json", "yarn.lock"], widget))
    policy = (
        ENFORCE
        + "waivers:\n  - rule: CVE-2099-0001\n    path: package-lock.json\n"
        + "    expires: 2026-12-31\n    approved_by: sec\n"
    )

    outcome = gate(head, frozenset(), policy=policy)

    assert [d.outcome for d in outcome.decisions] == [Outcome.WAIVED]
    assert outcome.conclusion is Conclusion.SUCCESS
