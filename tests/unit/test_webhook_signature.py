from __future__ import annotations

import hashlib
import hmac

import pytest

from newsoc_code.github.signature import sign, verify_signature

SECRET = b"It's a Secret to Everybody"
BODY = b"Hello, World!"
# The example in GitHub's documentation for validating webhook deliveries.
GITHUB_DOCS_SIGNATURE = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"


def test_matches_the_example_in_githubs_documentation() -> None:
    assert verify_signature(SECRET, BODY, GITHUB_DOCS_SIGNATURE)


def test_sign_round_trips() -> None:
    assert verify_signature(SECRET, b'{"a":1}', sign(SECRET, b'{"a":1}'))


@pytest.mark.parametrize(
    "header",
    [
        None,
        "",
        "sha256=",
        "sha256=" + "0" * 64,
        GITHUB_DOCS_SIGNATURE.upper(),  # hex is case sensitive here: GitHub sends lowercase
        GITHUB_DOCS_SIGNATURE.replace("sha256=", "sha1="),
        GITHUB_DOCS_SIGNATURE[len("sha256=") :],  # prefix missing
        "sha256=" + "é" * 64,  # non-ASCII must not raise
    ],
)
def test_rejects_malformed_or_wrong_signatures(header: str | None) -> None:
    assert not verify_signature(SECRET, BODY, header)


def test_rejects_a_tampered_body() -> None:
    assert not verify_signature(SECRET, BODY + b" ", GITHUB_DOCS_SIGNATURE)


def test_rejects_a_signature_made_with_another_secret() -> None:
    assert not verify_signature(b"other", BODY, GITHUB_DOCS_SIGNATURE)


def test_an_empty_secret_never_verifies() -> None:
    """With no secret configured, an attacker could otherwise sign with the empty key."""
    forged = "sha256=" + hmac.new(b"", BODY, hashlib.sha256).hexdigest()
    assert not verify_signature(b"", BODY, forged)


def test_the_legacy_sha1_header_value_is_not_accepted() -> None:
    legacy = "sha1=" + hmac.new(SECRET, BODY, hashlib.sha1).hexdigest()
    assert not verify_signature(SECRET, BODY, legacy)
