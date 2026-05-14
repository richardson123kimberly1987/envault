"""Secret value transformation utilities for envault."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

TRANSFORM_OPS: list[str] = ["uppercase", "lowercase", "strip", "reverse", "base64encode", "base64decode"]


class TransformError(Exception):
    """Raised when a transformation operation fails."""


@dataclass
class TransformResult:
    secret: str
    environment: str
    operation: str
    original: str
    transformed: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "secret": self.secret,
            "environment": self.environment,
            "operation": self.operation,
            "original": self.original,
            "transformed": self.transformed,
        }


def _get_entry_or_raise(vault: Any, environment: str, secret: str) -> Any:
    entry = vault.get_secret(environment, secret)
    if entry is None:
        raise TransformError(f"Secret '{secret}' not found in environment '{environment}'")
    return entry


def transform_secret(
    vault: Any,
    environment: str,
    secret: str,
    operation: str,
    passphrase: str,
) -> TransformResult:
    """Apply a named transformation to a secret value and persist the result."""
    if operation not in TRANSFORM_OPS:
        raise TransformError(
            f"Unknown operation '{operation}'. Valid ops: {TRANSFORM_OPS}"
        )

    entry = _get_entry_or_raise(vault, environment, secret)
    original = entry.decrypt(passphrase)

    import base64

    if operation == "uppercase":
        transformed = original.upper()
    elif operation == "lowercase":
        transformed = original.lower()
    elif operation == "strip":
        transformed = original.strip()
    elif operation == "reverse":
        transformed = original[::-1]
    elif operation == "base64encode":
        transformed = base64.b64encode(original.encode()).decode()
    elif operation == "base64decode":
        try:
            transformed = base64.b64decode(original.encode()).decode()
        except Exception as exc:
            raise TransformError(f"base64decode failed: {exc}") from exc
    else:  # pragma: no cover
        transformed = original

    entry.update_value(transformed, passphrase)
    vault.save()

    return TransformResult(
        secret=secret,
        environment=environment,
        operation=operation,
        original=original,
        transformed=transformed,
    )
