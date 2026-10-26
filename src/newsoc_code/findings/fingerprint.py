"""Stable fingerprints for dedupe, baselines and waivers.

Rules that make a fingerprint useful:
* Never include a line number: findings must survive unrelated edits above them.
* Normalise whitespace in matched text so reformatting does not create "new" findings.
* Never include a secret value. Secrets are represented by a keyed hash so the same secret
  can be matched across commits without the value ever being stored.
"""

from __future__ import annotations

import hashlib
import hmac
import re

_WS = re.compile(r"\s+")
_SEP = "\x1f"


def normalise_text(text: str) -> str:
    return _WS.sub(" ", text).strip()


def _digest(*parts: str) -> str:
    return hashlib.sha256(_SEP.join(parts).encode("utf-8")).hexdigest()


def sast_fingerprint(rule_id: str, path: str, match_text: str, occurrence: int) -> str:
    """``occurrence`` is the index of this match among identical matches of the rule in the file."""
    return _digest("sast", rule_id, path, normalise_text(match_text), str(occurrence))


def sca_fingerprint(ecosystem: str, package: str, manifest_path: str, vuln_id: str) -> str:
    return _digest("sca", ecosystem.lower(), package.lower(), manifest_path, vuln_id)


def secret_hash(value: str, salt: bytes) -> str:
    """Keyed hash of a secret value. The value itself is discarded by the caller."""
    return hmac.new(salt, value.encode("utf-8"), hashlib.sha256).hexdigest()


def secrets_fingerprint(rule_id: str, hashed_value: str) -> str:
    """The path is deliberately excluded: one secret is one finding with several locations."""
    return _digest("secrets", rule_id, hashed_value)


def iac_fingerprint(check_id: str, path: str, resource: str) -> str:
    return _digest("iac", check_id, path, resource)
