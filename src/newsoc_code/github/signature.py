"""Verification of GitHub's ``X-Hub-Signature-256`` webhook header."""

from __future__ import annotations

import hashlib
import hmac

PREFIX = "sha256="


def sign(secret: bytes, body: bytes) -> str:
    """The header value GitHub would send for ``body`` (used by tests and ``replay-webhook``)."""
    return PREFIX + hmac.new(secret, body, hashlib.sha256).hexdigest()


def verify_signature(secret: bytes, body: bytes, header: str | None) -> bool:
    """True only for a well-formed sha256 signature that matches, in constant time.

    The older ``X-Hub-Signature`` (sha1) header is deliberately not accepted.
    """
    if not secret or not header or not header.startswith(PREFIX):
        return False
    expected = sign(secret, body).encode()
    return hmac.compare_digest(expected, header.encode("utf-8", "replace"))
