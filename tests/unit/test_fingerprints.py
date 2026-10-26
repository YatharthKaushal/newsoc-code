from __future__ import annotations

import hashlib

from newsoc_code.findings.fingerprint import (
    SCHEME_VERSION,
    iac_fingerprint,
    normalise_package,
    project_dir,
    sast_fingerprint,
    sca_fingerprint,
    secret_hash,
    secrets_fingerprint,
)


def test_sast_fingerprint_ignores_reformatting_but_not_content():
    base = sast_fingerprint("r", "a.py", "x = foo(bar)", 0)
    # same tokens, different spacing and line breaks: the same finding
    assert sast_fingerprint("r", "a.py", "x   =\n    foo(bar)", 0) == base
    # a different argument is a different finding
    assert sast_fingerprint("r", "a.py", "x = foo(baz)", 0) != base
    # and the rule and file are part of the identity
    assert sast_fingerprint("other", "a.py", "x = foo(bar)", 0) != base
    assert sast_fingerprint("r", "b.py", "x = foo(bar)", 0) != base


def test_identical_matches_in_one_file_get_distinct_fingerprints():
    assert sast_fingerprint("r", "a.py", "x", 0) != sast_fingerprint("r", "a.py", "x", 1)


def test_secret_fingerprint_is_independent_of_the_path_and_the_value_is_not_recoverable():
    h = secret_hash("hunter2-hunter2-hunter2-hunter2", b"salt")
    assert "hunter2" not in h
    assert secrets_fingerprint("rule", h) == secrets_fingerprint("rule", h)
    assert secret_hash("v", b"salt-a") != secret_hash("v", b"salt-b")


def test_sca_fingerprint_is_case_insensitive_on_ecosystem_and_package_only():
    assert sca_fingerprint("npm", "Lodash", "app", "CVE-1") == sca_fingerprint(
        "NPM", "lodash", "app", "CVE-1"
    )
    assert sca_fingerprint("npm", "lodash", "a", "CVE-1") != sca_fingerprint(
        "npm", "lodash", "b", "CVE-1"
    )
    assert sca_fingerprint("npm", "lodash", "a", "CVE-1") != sca_fingerprint(
        "npm", "lodash", "a", "CVE-2"
    )
    assert sca_fingerprint("npm", "lodash", "a", "CVE-1") != sca_fingerprint(
        "PyPI", "lodash", "a", "CVE-1"
    )


def test_sca_fingerprint_keys_on_the_project_directory_not_on_which_lockfile_lists_it():
    """A baseline made with ``package-lock.json`` and ``yarn.lock`` must still match when one of
    them is later removed, so the lockfile name is not an input; the directory is."""
    from_npm = sca_fingerprint("npm", "lodash", project_dir("apps/web/package-lock.json"), "CVE-1")
    from_yarn = sca_fingerprint("npm", "lodash", project_dir("apps/web/yarn.lock"), "CVE-1")
    assert from_npm == from_yarn
    assert from_npm != sca_fingerprint("npm", "lodash", project_dir("apps/api/yarn.lock"), "CVE-1")
    assert from_npm != sca_fingerprint("npm", "lodash", project_dir("yarn.lock"), "CVE-1")


def test_sca_fingerprint_treats_every_spelling_of_the_repository_root_alike():
    root = sca_fingerprint("npm", "lodash", "", "CVE-1")
    assert root == sca_fingerprint("npm", "lodash", ".", "CVE-1")
    assert root == sca_fingerprint("npm", "lodash", "./", "CVE-1")
    assert root == sca_fingerprint("npm", "lodash", project_dir("yarn.lock"), "CVE-1")
    assert sca_fingerprint("npm", "lodash", "apps/web/", "CVE-1") == sca_fingerprint(
        "npm", "lodash", "apps/web", "CVE-1"
    )


def test_sca_fingerprint_folds_pypi_name_separators_only_for_pypi():
    assert sca_fingerprint("PyPI", "Acme_Yaml.Tools", "", "CVE-1") == sca_fingerprint(
        "PyPI", "acme-yaml-tools", "", "CVE-1"
    )
    assert sca_fingerprint("npm", "acme_tools", "", "CVE-1") != sca_fingerprint(
        "npm", "acme-tools", "", "CVE-1"
    )
    assert normalise_package("PyPI", "Zope.Interface") == "zope-interface"


def test_sca_fingerprint_inputs_are_pinned():
    """The exact recipe, so another implementation can reproduce it. If this fails after a
    deliberate change, raise ``fingerprint.SCHEME_VERSION`` too, so cached baselines made under the
    old recipe are not compared with the new fingerprints."""
    recipe = "\x1f".join(["sca-project", "npm", "lodash", "apps/web", "CVE-2020-28500"])
    assert (
        sca_fingerprint("npm", "Lodash", "apps/web", "CVE-2020-28500")
        == hashlib.sha256(recipe.encode()).hexdigest()
    )
    assert SCHEME_VERSION == 2


def test_cached_baselines_are_keyed_on_the_fingerprint_scheme(monkeypatch):
    from newsoc_code import pipeline

    before = pipeline.scanner_key([], "rules1", "osv1")
    monkeypatch.setattr(pipeline, "FINGERPRINT_SCHEME", pipeline.FINGERPRINT_SCHEME + 1)
    assert pipeline.scanner_key([], "rules1", "osv1") != before


def test_iac_fingerprint_keys_on_check_path_and_resource():
    assert iac_fingerprint("C", "main.tf", "r.a") != iac_fingerprint("C", "main.tf", "r.b")
