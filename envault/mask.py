"""Secret masking utilities for envault."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

MASK_CHAR = "*"
DEFAULT_VISIBLE_CHARS = 4
MIN_SECRET_LENGTH_FOR_PARTIAL = 8


class MaskError(Exception):
    """Raised when masking operations fail."""


@dataclass
class MaskResult:
    key: str
    environment: str
    original_length: int
    masked_value: str
    strategy: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "environment": self.environment,
            "original_length": self.original_length,
            "masked_value": self.masked_value,
            "strategy": self.strategy,
        }


def mask_full(value: str) -> str:
    """Replace the entire value with mask characters."""
    return MASK_CHAR * max(len(value), 8)


def mask_partial(value: str, visible: int = DEFAULT_VISIBLE_CHARS) -> str:
    """Show only the last `visible` characters; mask the rest."""
    if len(value) < MIN_SECRET_LENGTH_FOR_PARTIAL:
        return mask_full(value)
    hidden = max(len(value) - visible, visible)
    return MASK_CHAR * hidden + value[-visible:]


def mask_secret(
    vault: Any,
    environment: str,
    key: str,
    strategy: str = "full",
    visible: int = DEFAULT_VISIBLE_CHARS,
) -> MaskResult:
    """Return a MaskResult for a single secret without modifying the vault."""
    if strategy not in ("full", "partial"):
        raise MaskError(f"Unknown masking strategy: {strategy!r}. Use 'full' or 'partial'.")

    entry = vault.get_secret(environment, key)
    if entry is None:
        raise MaskError(f"Secret {key!r} not found in environment {environment!r}.")

    raw = entry.to_dict().get("value", "")
    if not isinstance(raw, str):
        raise MaskError(f"Secret value for {key!r} is not a string.")

    masked = mask_full(raw) if strategy == "full" else mask_partial(raw, visible)

    return MaskResult(
        key=key,
        environment=environment,
        original_length=len(raw),
        masked_value=masked,
        strategy=strategy,
    )


def mask_all(
    vault: Any,
    environment: str,
    strategy: str = "full",
    visible: int = DEFAULT_VISIBLE_CHARS,
) -> list[MaskResult]:
    """Return MaskResult objects for every secret in an environment."""
    results: list[MaskResult] = []
    for key in vault.list_secrets(environment):
        results.append(mask_secret(vault, environment, key, strategy=strategy, visible=visible))
    return results
