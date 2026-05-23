"""Retire (soft-delete) secrets, marking them as no longer active."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

RETIRE_STATES = ("active", "retired")


class RetireError(Exception):
    """Raised when a retire/unretire operation fails."""


@dataclass
class RetireResult:
    secret: str
    environment: str
    state: str
    retired_at: str | None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "secret": self.secret,
            "environment": self.environment,
            "state": self.state,
            "retired_at": self.retired_at,
            "metadata": self.metadata,
        }


def _get_entry_or_raise(vault: Any, environment: str, secret: str) -> Any:
    entry = vault.get_secret(environment, secret)
    if entry is None:
        raise RetireError(f"Secret '{secret}' not found in environment '{environment}'")
    return entry


def retire_secret(vault: Any, environment: str, secret: str) -> RetireResult:
    """Mark a secret as retired."""
    entry = _get_entry_or_raise(vault, environment, secret)
    now = datetime.now(timezone.utc).isoformat()
    meta = dict(entry.to_dict().get("metadata", {}))
    meta["retired"] = True
    meta["retired_at"] = now
    entry.update_value(entry.to_dict().get("value", ""), metadata=meta)
    vault.save()
    return RetireResult(
        secret=secret,
        environment=environment,
        state="retired",
        retired_at=now,
        metadata=meta,
    )


def unretire_secret(vault: Any, environment: str, secret: str) -> RetireResult:
    """Remove the retired flag from a secret."""
    entry = _get_entry_or_raise(vault, environment, secret)
    meta = dict(entry.to_dict().get("metadata", {}))
    meta.pop("retired", None)
    retired_at = meta.pop("retired_at", None)
    entry.update_value(entry.to_dict().get("value", ""), metadata=meta)
    vault.save()
    return RetireResult(
        secret=secret,
        environment=environment,
        state="active",
        retired_at=retired_at,
        metadata=meta,
    )


def list_retired(vault: Any, environment: str) -> list[RetireResult]:
    """Return all retired secrets in an environment."""
    results: list[RetireResult] = []
    for name in vault.list_secrets(environment):
        entry = vault.get_secret(environment, name)
        if entry is None:
            continue
        d = entry.to_dict()
        meta = d.get("metadata", {})
        if meta.get("retired"):
            results.append(
                RetireResult(
                    secret=name,
                    environment=environment,
                    state="retired",
                    retired_at=meta.get("retired_at"),
                    metadata=dict(meta),
                )
            )
    return results
