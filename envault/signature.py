"""Signature module: sign and verify secret values using HMAC."""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Optional

SIGNATURE_ALGORITHM = "sha256"


class SignatureError(Exception):
    """Raised when a signature operation fails."""


@dataclass
class SignatureResult:
    key: str
    environment: str
    algorithm: str
    signature: str
    verified: bool

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "environment": self.environment,
            "algorithm": self.algorithm,
            "signature": self.signature,
            "verified": self.verified,
        }


def _get_entry_or_raise(vault, environment: str, key: str):
    entry = vault.get_secret(environment, key)
    if entry is None:
        raise SignatureError(f"Secret '{key}' not found in environment '{environment}'")
    return entry


def sign_secret(vault, environment: str, key: str, passphrase: str) -> SignatureResult:
    """Compute an HMAC-SHA256 signature for a secret value."""
    entry = _get_entry_or_raise(vault, environment, key)
    raw = entry.to_dict().get("value", "")
    sig = hmac.new(
        passphrase.encode(), raw.encode(), getattr(hashlib, SIGNATURE_ALGORITHM)
    ).hexdigest()
    return SignatureResult(
        key=key,
        environment=environment,
        algorithm=SIGNATURE_ALGORITHM,
        signature=sig,
        verified=True,
    )


def verify_secret(
    vault, environment: str, key: str, passphrase: str, expected: str
) -> SignatureResult:
    """Verify that a secret value matches the expected HMAC-SHA256 signature."""
    entry = _get_entry_or_raise(vault, environment, key)
    raw = entry.to_dict().get("value", "")
    computed = hmac.new(
        passphrase.encode(), raw.encode(), getattr(hashlib, SIGNATURE_ALGORITHM)
    ).hexdigest()
    verified = hmac.compare_digest(computed, expected)
    return SignatureResult(
        key=key,
        environment=environment,
        algorithm=SIGNATURE_ALGORITHM,
        signature=computed,
        verified=verified,
    )
