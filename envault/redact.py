"""Redaction utilities for masking secret values in output."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

REDACT_PLACEHOLDER = "***"
REDACT_PARTIAL_CHARS = 4


class RedactError(Exception):
    """Raised when redaction fails."""


@dataclass
class RedactResult:
    key: str
    original_length: int
    redacted_value: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "original_length": self.original_length,
            "redacted_value": self.redacted_value,
        }


def redact_full(value: str) -> str:
    """Fully redact a value."""
    return REDACT_PLACEHOLDER


def redact_partial(value: str, visible_chars: int = REDACT_PARTIAL_CHARS) -> str:
    """Show only the last N characters, masking the rest."""
    if not value:
        return REDACT_PLACEHOLDER
    if len(value) <= visible_chars:
        return REDACT_PLACEHOLDER
    return "*" * (len(value) - visible_chars) + value[-visible_chars:]


def redact_secret(key: str, value: str, partial: bool = False) -> RedactResult:
    """Redact a single secret value."""
    if not isinstance(value, str):
        raise RedactError(f"Value for '{key}' must be a string")
    redacted = redact_partial(value) if partial else redact_full(value)
    return RedactResult(key=key, original_length=len(value), redacted_value=redacted)


def redact_all(vault: Any, environment: str, partial: bool = False) -> list[RedactResult]:
    """Redact all secrets in an environment."""
    results: list[RedactResult] = []
    for key in vault.list_secrets(environment):
        entry = vault.get_secret(environment, key)
        if entry is None:
            continue
        raw = entry.to_dict().get("value", "")
        results.append(redact_secret(key, raw, partial=partial))
    return results
