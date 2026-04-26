"""Fingerprint module: generate and verify content fingerprints for secrets."""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Optional

FINGERPRINT_ALGORITHMS = ("sha256", "sha512", "md5")


class FingerprintError(Exception):
    """Raised when a fingerprint operation fails."""


@dataclass
class FingerprintResult:
    key: str
    environment: str
    algorithm: str
    fingerprint: str
    matched: Optional[bool] = None

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "environment": self.environment,
            "algorithm": self.algorithm,
            "fingerprint": self.fingerprint,
            "matched": self.matched,
        }


def _compute(value: str, algorithm: str) -> str:
    if algorithm not in FINGERPRINT_ALGORITHMS:
        raise FingerprintError(
            f"Unsupported algorithm '{algorithm}'. "
            f"Choose from: {', '.join(FINGERPRINT_ALGORITHMS)}"
        )
    h = hashlib.new(algorithm, value.encode())
    return h.hexdigest()


def fingerprint_secret(
    vault,
    key: str,
    environment: str,
    algorithm: str = "sha256",
) -> FingerprintResult:
    """Compute a fingerprint for the current value of a secret."""
    entry = vault.get_secret(key, environment)
    if entry is None:
        raise FingerprintError(
            f"Secret '{key}' not found in environment '{environment}'."
        )
    value = entry.to_dict().get("value", "")
    fp = _compute(value, algorithm)
    return FingerprintResult(
        key=key,
        environment=environment,
        algorithm=algorithm,
        fingerprint=fp,
    )


def verify_fingerprint(
    vault,
    key: str,
    environment: str,
    expected: str,
    algorithm: str = "sha256",
) -> FingerprintResult:
    """Verify that the current secret value matches the expected fingerprint."""
    result = fingerprint_secret(vault, key, environment, algorithm)
    result.matched = hmac.compare_digest(result.fingerprint, expected)
    return result
