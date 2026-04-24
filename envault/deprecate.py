"""Mark secrets as deprecated with optional replacement hints."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

DEPRECATION_KEY = "__deprecated__"
REPLACEMENT_KEY = "__replacement__"


class DeprecateError(Exception):
    """Raised when a deprecation operation fails."""


@dataclass
class DeprecateResult:
    environment: str
    secret: str
    deprecated: bool
    replacement: Optional[str]
    timestamp: str

    def to_dict(self) -> dict:
        return {
            "environment": self.environment,
            "secret": self.secret,
            "deprecated": self.deprecated,
            "replacement": self.replacement,
            "timestamp": self.timestamp,
        }


def deprecate_secret(
    vault,
    environment: str,
    secret: str,
    replacement: Optional[str] = None,
) -> DeprecateResult:
    """Mark *secret* in *environment* as deprecated."""
    entry = vault.get_secret(environment, secret)
    if entry is None:
        raise DeprecateError(
            f"Secret '{secret}' not found in environment '{environment}'."
        )

    data = entry.to_dict()
    data[DEPRECATION_KEY] = True
    data[REPLACEMENT_KEY] = replacement
    vault.set_secret(environment, secret, data["value"], metadata=data)

    return DeprecateResult(
        environment=environment,
        secret=secret,
        deprecated=True,
        replacement=replacement,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


def undeprecate_secret(vault, environment: str, secret: str) -> DeprecateResult:
    """Remove the deprecation marker from *secret* in *environment*."""
    entry = vault.get_secret(environment, secret)
    if entry is None:
        raise DeprecateError(
            f"Secret '{secret}' not found in environment '{environment}'."
        )

    data = entry.to_dict()
    data.pop(DEPRECATION_KEY, None)
    data.pop(REPLACEMENT_KEY, None)
    vault.set_secret(environment, secret, data["value"], metadata=data)

    return DeprecateResult(
        environment=environment,
        secret=secret,
        deprecated=False,
        replacement=None,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


def list_deprecated(vault, environment: str) -> list[DeprecateResult]:
    """Return all deprecated secrets in *environment*."""
    results = []
    for name in vault.list_secrets(environment):
        entry = vault.get_secret(environment, name)
        if entry is None:
            continue
        data = entry.to_dict()
        if data.get(DEPRECATION_KEY):
            results.append(
                DeprecateResult(
                    environment=environment,
                    secret=name,
                    deprecated=True,
                    replacement=data.get(REPLACEMENT_KEY),
                    timestamp=data.get("updated_at", ""),
                )
            )
    return results
