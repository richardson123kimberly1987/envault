"""Truncate module for envault.

Provides functionality to truncate secret values to a maximum length,
optionally preserving a prefix or suffix for identification purposes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

TRUNCATE_STRATEGIES = ["end", "start", "middle"]


class TruncateError(Exception):
    """Raised when a truncation operation fails."""


@dataclass
class TruncateResult:
    """Result of a truncate operation."""

    secret: str
    environment: str
    original_length: int
    truncated_length: int
    strategy: str
    changed: bool

    def to_dict(self) -> dict:
        return {
            "secret": self.secret,
            "environment": self.environment,
            "original_length": self.original_length,
            "truncated_length": self.truncated_length,
            "strategy": self.strategy,
            "changed": self.changed,
        }


def _apply_truncate(value: str, max_length: int, strategy: str) -> str:
    """Apply truncation to a string value using the given strategy."""
    if len(value) <= max_length:
        return value

    if strategy == "end":
        return value[:max_length]
    elif strategy == "start":
        return value[-max_length:]
    elif strategy == "middle":
        # Keep equal parts from start and end, remove the middle
        half = max_length // 2
        remainder = max_length - half
        return value[:remainder] + value[len(value) - half:]
    else:
        raise TruncateError(f"Unknown truncation strategy: {strategy!r}. "
                            f"Choose from: {TRUNCATE_STRATEGIES}")


def truncate_secret(
    vault,
    environment: str,
    secret: str,
    max_length: int,
    strategy: str = "end",
    passphrase: str = "",
) -> TruncateResult:
    """Truncate the value of a secret to at most *max_length* characters.

    Args:
        vault: Vault instance.
        environment: Environment name.
        secret: Secret key name.
        max_length: Maximum allowed length for the secret value.
        strategy: One of 'end' (default), 'start', or 'middle'.
        passphrase: Passphrase used to decrypt/re-encrypt the secret.

    Returns:
        TruncateResult describing what happened.

    Raises:
        TruncateError: If the secret is not found, max_length is invalid,
                       or an unknown strategy is given.
    """
    if max_length < 1:
        raise TruncateError(f"max_length must be at least 1, got {max_length}.")

    if strategy not in TRUNCATE_STRATEGIES:
        raise TruncateError(
            f"Unknown truncation strategy: {strategy!r}. "
            f"Choose from: {TRUNCATE_STRATEGIES}"
        )

    entry = vault.get_secret(environment, secret)
    if entry is None:
        raise TruncateError(
            f"Secret {secret!r} not found in environment {environment!r}."
        )

    original_value: str = entry.decrypt(passphrase)
    original_length = len(original_value)

    truncated_value = _apply_truncate(original_value, max_length, strategy)
    truncated_length = len(truncated_value)
    changed = truncated_value != original_value

    if changed:
        entry.update_value(truncated_value, passphrase)
        vault.save()

    return TruncateResult(
        secret=secret,
        environment=environment,
        original_length=original_length,
        truncated_length=truncated_length,
        strategy=strategy,
        changed=changed,
    )


def truncate_all(
    vault,
    environment: str,
    max_length: int,
    strategy: str = "end",
    passphrase: str = "",
) -> list[TruncateResult]:
    """Truncate all secrets in an environment to at most *max_length* characters.

    Args:
        vault: Vault instance.
        environment: Environment name.
        max_length: Maximum allowed length for each secret value.
        strategy: Truncation strategy ('end', 'start', or 'middle').
        passphrase: Passphrase used to decrypt/re-encrypt secrets.

    Returns:
        List of TruncateResult objects, one per secret.

    Raises:
        TruncateError: If max_length is invalid or strategy is unknown.
    """
    results: list[TruncateResult] = []
    for key in vault.list_secrets(environment):
        result = truncate_secret(
            vault, environment, key, max_length, strategy, passphrase
        )
        results.append(result)
    return results
