"""Digest module: compute and verify content digests for secrets."""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Optional

DIGEST_ALGORITHMS = ("sha256", "sha512", "md5")


class DigestError(Exception):
    """Raised when a digest operation fails."""


@dataclass
class DigestResult:
    secret_name: str
    environment: str
    algorithm: str
    digest: str
    verified: Optional[bool] = None

    def to_dict(self) -> dict:
        return {
            "secret_name": self.secret_name,
            "environment": self.environment,
            "algorithm": self.algorithm,
            "digest": self.digest,
            "verified": self.verified,
        }


def _get_entry_or_raise(vault, environment: str, secret_name: str):
    entry = vault.get_secret(environment, secret_name)
    if entry is None:
        raise DigestError(
            f"Secret '{secret_name}' not found in environment '{environment}'."
        )
    return entry


def compute_digest(vault, environment: str, secret_name: str, algorithm: str = "sha256") -> DigestResult:
    """Compute a digest of the secret's plaintext value."""
    if algorithm not in DIGEST_ALGORITHMS:
        raise DigestError(
            f"Unsupported algorithm '{algorithm}'. Choose from: {DIGEST_ALGORITHMS}."
        )
    entry = _get_entry_or_raise(vault, environment, secret_name)
    plaintext = entry.decrypt()
    h = hashlib.new(algorithm, plaintext.encode())
    return DigestResult(
        secret_name=secret_name,
        environment=environment,
        algorithm=algorithm,
        digest=h.hexdigest(),
    )


def verify_digest(vault, environment: str, secret_name: str, expected: str, algorithm: str = "sha256") -> DigestResult:
    """Verify that the secret's digest matches an expected value."""
    result = compute_digest(vault, environment, secret_name, algorithm)
    result.verified = hmac.compare_digest(result.digest, expected)
    return result
