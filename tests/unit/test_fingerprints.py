from __future__ import annotations

from newsoc_code.findings.fingerprint import (
    iac_fingerprint,
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
    assert sca_fingerprint("npm", "Lodash", "package-lock.json", "CVE-1") == sca_fingerprint(
        "NPM", "lodash", "package-lock.json", "CVE-1"
    )
    assert sca_fingerprint("npm", "lodash", "a/package-lock.json", "CVE-1") != sca_fingerprint(
        "npm", "lodash", "b/package-lock.json", "CVE-1"
    )


def test_iac_fingerprint_keys_on_check_path_and_resource():
    assert iac_fingerprint("C", "main.tf", "r.a") != iac_fingerprint("C", "main.tf", "r.b")
