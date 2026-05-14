"""Checksum computation and verification for secret values."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

CHECKSUM_ALGORITHMS = ("sha256", "sha512", "md5")


class ChecksumError(Exception):
    """Raised when a checksum operation fails."""


@dataclass
class ChecksumResult:
    secret_name: str
    environment: str
    algorithm: str
    checksum: str
    verified: Optional[bool] = None

    def to_dict(self) -> dict:
        return {
            "secret_name": self.secret_name,
            "environment": self.environment,
            "algorithm": self.algorithm,
            "checksum": self.checksum,
            "verified": self.verified,
        }


def _get_entry_or_raise(vault, environment: str, secret_name: str):
    entry = vault.get_secret(environment, secret_name)
    if entry is None:
        raise ChecksumError(
            f"Secret '{secret_name}' not found in environment '{environment}'."
        )
    return entry


def compute_checksum(
    vault, environment: str, secret_name: str, algorithm: str = "sha256"
) -> ChecksumResult:
    """Compute a checksum of a secret's plaintext value."""
    if algorithm not in CHECKSUM_ALGORITHMS:
        raise ChecksumError(
            f"Unsupported algorithm '{algorithm}'. "
            f"Choose from: {', '.join(CHECKSUM_ALGORITHMS)}."
        )
    entry = _get_entry_or_raise(vault, environment, secret_name)
    plaintext = entry.decrypt()
    digest = hashlib.new(algorithm, plaintext.encode()).hexdigest()
    return ChecksumResult(
        secret_name=secret_name,
        environment=environment,
        algorithm=algorithm,
        checksum=digest,
    )


def verify_checksum(
    vault,
    environment: str,
    secret_name: str,
    expected: str,
    algorithm: str = "sha256",
) -> ChecksumResult:
    """Verify a secret's checksum against an expected value."""
    result = compute_checksum(vault, environment, secret_name, algorithm)
    result.verified = result.checksum == expected
    return result
