"""Tokenize secrets — replace secret values with opaque tokens."""
from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass, field
from typing import Dict, Optional

TOKEN_PREFIX = "evtok_"


class TokenizeError(Exception):
    """Raised when tokenization fails."""


@dataclass
class TokenizeResult:
    key: str
    environment: str
    token: str
    replaced: bool

    def to_dict(self) -> Dict:
        return {
            "key": self.key,
            "environment": self.environment,
            "token": self.token,
            "replaced": self.replaced,
        }


def _get_entry_or_raise(vault, key: str, environment: str):
    entry = vault.get_secret(key, environment)
    if entry is None:
        raise TokenizeError(f"Secret '{key}' not found in environment '{environment}'")
    return entry


def _generate_token(key: str, environment: str, seed: Optional[bytes] = None) -> str:
    """Generate a deterministic token from key + environment + seed."""
    seed = seed or os.urandom(16)
    raw = f"{key}:{environment}".encode() + seed
    digest = hashlib.sha256(raw).hexdigest()[:32]
    return f"{TOKEN_PREFIX}{digest}"


def tokenize_secret(
    vault,
    key: str,
    environment: str,
    *,
    seed: Optional[bytes] = None,
) -> TokenizeResult:
    """Replace a secret's value with an opaque token and store the token."""
    entry = _get_entry_or_raise(vault, key, environment)
    token = _generate_token(key, environment, seed=seed)
    metadata = entry.to_dict().get("metadata", {}) or {}
    already_tokenized = metadata.get("token") == token
    entry.update_value(token)
    vault.set_secret(key, environment, entry)
    return TokenizeResult(
        key=key,
        environment=environment,
        token=token,
        replaced=not already_tokenized,
    )


def detokenize_secret(
    vault,
    key: str,
    environment: str,
    original_value: str,
) -> TokenizeResult:
    """Restore a secret's value from a token back to the original plaintext."""
    entry = _get_entry_or_raise(vault, key, environment)
    current = entry.decrypt() if hasattr(entry, "decrypt") else entry.to_dict().get("value", "")
    if not current.startswith(TOKEN_PREFIX):
        raise TokenizeError(f"Secret '{key}' in '{environment}' does not appear to be tokenized")
    entry.update_value(original_value)
    vault.set_secret(key, environment, entry)
    return TokenizeResult(
        key=key,
        environment=environment,
        token=current,
        replaced=True,
    )
