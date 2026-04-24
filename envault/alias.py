"""Secret aliasing — create named aliases that point to existing secrets."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


class AliasError(Exception):
    """Raised when an alias operation fails."""


@dataclass
class AliasResult:
    alias: str
    target_key: str
    environment: str
    resolved_value: Optional[str]
    action: str  # "created" | "removed" | "resolved"

    def to_dict(self) -> dict:
        return {
            "alias": self.alias,
            "target_key": self.target_key,
            "environment": self.environment,
            "resolved_value": self.resolved_value,
            "action": self.action,
        }


def add_alias(vault, environment: str, alias: str, target_key: str) -> AliasResult:
    """Register *alias* as a pointer to *target_key* in *environment*."""
    if vault.get_secret(environment, target_key) is None:
        raise AliasError(
            f"Target secret '{target_key}' not found in environment '{environment}'."
        )

    meta = vault.get_secret(environment, alias)
    if meta is not None:
        raise AliasError(
            f"A secret or alias named '{alias}' already exists in '{environment}'."
        )

    # Store alias as a special secret whose value encodes the target.
    vault.set_secret(environment, alias, f"__alias__:{target_key}")
    return AliasResult(
        alias=alias,
        target_key=target_key,
        environment=environment,
        resolved_value=None,
        action="created",
    )


def remove_alias(vault, environment: str, alias: str) -> AliasResult:
    """Remove an alias from *environment*."""
    entry = vault.get_secret(environment, alias)
    if entry is None:
        raise AliasError(f"Alias '{alias}' not found in environment '{environment}'.")

    raw = entry.to_dict().get("value", "")
    if not raw.startswith("__alias__:"):
        raise AliasError(f"'{alias}' is not an alias — use the normal delete command.")

    target_key = raw[len("__alias__:"):]
    vault.delete_secret(environment, alias)
    return AliasResult(
        alias=alias,
        target_key=target_key,
        environment=environment,
        resolved_value=None,
        action="removed",
    )


def resolve_alias(vault, environment: str, alias: str) -> AliasResult:
    """Follow *alias* and return the value of its target secret."""
    entry = vault.get_secret(environment, alias)
    if entry is None:
        raise AliasError(f"Alias '{alias}' not found in environment '{environment}'.")

    raw = entry.to_dict().get("value", "")
    if not raw.startswith("__alias__:"):
        raise AliasError(f"'{alias}' is not an alias.")

    target_key = raw[len("__alias__:"):]
    target_entry = vault.get_secret(environment, target_key)
    if target_entry is None:
        raise AliasError(
            f"Alias '{alias}' points to missing secret '{target_key}'."
        )

    resolved_value = target_entry.to_dict().get("value")
    return AliasResult(
        alias=alias,
        target_key=target_key,
        environment=environment,
        resolved_value=resolved_value,
        action="resolved",
    )
