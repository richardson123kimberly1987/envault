"""Obfuscation utilities for secret values in envault."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

OBFUSCATE_STYLES = ("asterisk", "hash", "partial", "full")


class ObfuscateError(Exception):
    """Raised when obfuscation fails."""


@dataclass
class ObfuscateResult:
    key: str
    environment: str
    original_length: int
    obfuscated: str
    style: str

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "environment": self.environment,
            "original_length": self.original_length,
            "obfuscated": self.obfuscated,
            "style": self.style,
        }


def _get_entry_or_raise(vault, environment: str, key: str):
    entry = vault.get_secret(environment, key)
    if entry is None:
        raise ObfuscateError(f"Secret '{key}' not found in environment '{environment}'")
    return entry


def obfuscate_secret(
    vault,
    environment: str,
    key: str,
    style: str = "partial",
    passphrase: str = "",
) -> ObfuscateResult:
    """Return an obfuscated representation of a secret value."""
    if style not in OBFUSCATE_STYLES:
        raise ObfuscateError(
            f"Unknown style '{style}'. Choose from: {', '.join(OBFUSCATE_STYLES)}"
        )
    entry = _get_entry_or_raise(vault, environment, key)
    try:
        plaintext: str = entry.decrypt(passphrase)
    except Exception as exc:
        raise ObfuscateError(f"Failed to decrypt secret '{key}': {exc}") from exc

    length = len(plaintext)

    if style == "full":
        obfuscated = "*" * length
    elif style == "asterisk":
        obfuscated = "*" * min(length, 8)
    elif style == "hash":
        obfuscated = "#" * min(length, 8)
    elif style == "partial":
        if length <= 4:
            obfuscated = "*" * length
        else:
            visible = max(1, length // 4)
            obfuscated = plaintext[:visible] + "*" * (length - visible)
    else:
        obfuscated = "*" * length

    return ObfuscateResult(
        key=key,
        environment=environment,
        original_length=length,
        obfuscated=obfuscated,
        style=style,
    )


def obfuscate_all(
    vault,
    environment: str,
    style: str = "partial",
    passphrase: str = "",
) -> list[ObfuscateResult]:
    """Obfuscate all secrets in the given environment."""
    results = []
    for key in vault.list_secrets(environment):
        results.append(obfuscate_secret(vault, environment, key, style, passphrase))
    return results
