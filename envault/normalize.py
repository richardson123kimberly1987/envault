"""Normalize secret values (trim whitespace, fix encoding, standardize line endings)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from envault.vault import Vault


class NormalizeError(Exception):
    """Raised when normalization fails."""


@dataclass
class NormalizeResult:
    key: str
    environment: str
    original: str
    normalized: str
    changed: bool

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "environment": self.environment,
            "original": self.original,
            "normalized": self.normalized,
            "changed": self.changed,
        }


def _apply_normalize(value: str) -> str:
    """Apply normalization rules to a secret value."""
    # Strip leading/trailing whitespace
    value = value.strip()
    # Normalize line endings to LF
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    # Ensure consistent UTF-8 encoding by round-tripping
    value = value.encode("utf-8", errors="replace").decode("utf-8")
    return value


def normalize_secret(
    vault: "Vault",
    key: str,
    environment: str,
    passphrase: str,
) -> NormalizeResult:
    """Normalize the value of a single secret in place."""
    entry = vault.get_secret(key, environment)
    if entry is None:
        raise NormalizeError(f"Secret '{key}' not found in environment '{environment}'")

    original = entry.decrypt(passphrase)
    normalized = _apply_normalize(original)
    changed = normalized != original

    if changed:
        entry.update_value(normalized, passphrase)
        vault.save()

    return NormalizeResult(
        key=key,
        environment=environment,
        original=original,
        normalized=normalized,
        changed=changed,
    )


def normalize_all(
    vault: "Vault",
    environment: str,
    passphrase: str,
) -> list[NormalizeResult]:
    """Normalize all secrets in an environment."""
    results = []
    for key in vault.list_secrets(environment):
        results.append(normalize_secret(vault, key, environment, passphrase))
    return results
