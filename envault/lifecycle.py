"""Lifecycle management for secrets: track creation, activation, deprecation, and expiry stages."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

LIFECYCLE_STAGES = ["active", "inactive", "deprecated", "expired", "archived"]


class LifecycleError(Exception):
    """Raised when a lifecycle operation fails."""


@dataclass
class LifecycleResult:
    secret: str
    environment: str
    previous_stage: Optional[str]
    current_stage: str
    changed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "secret": self.secret,
            "environment": self.environment,
            "previous_stage": self.previous_stage,
            "current_stage": self.current_stage,
            "changed_at": self.changed_at,
        }


def _get_entry_or_raise(vault, environment: str, secret: str):
    entry = vault.get_secret(environment, secret)
    if entry is None:
        raise LifecycleError(f"Secret '{secret}' not found in environment '{environment}'")
    return entry


def set_stage(vault, environment: str, secret: str, stage: str) -> LifecycleResult:
    """Transition a secret to the given lifecycle stage."""
    if stage not in LIFECYCLE_STAGES:
        raise LifecycleError(f"Invalid stage '{stage}'. Must be one of: {LIFECYCLE_STAGES}")
    entry = _get_entry_or_raise(vault, environment, secret)
    data = entry.to_dict()
    previous = data.get("lifecycle_stage", "active")
    data["lifecycle_stage"] = stage
    vault.set_secret(environment, secret, data["value"], metadata=data)
    return LifecycleResult(
        secret=secret,
        environment=environment,
        previous_stage=previous,
        current_stage=stage,
    )


def get_stage(vault, environment: str, secret: str) -> str:
    """Return the current lifecycle stage of a secret."""
    entry = _get_entry_or_raise(vault, environment, secret)
    return entry.to_dict().get("lifecycle_stage", "active")


def list_by_stage(vault, environment: str, stage: str) -> list[str]:
    """Return all secret names in the given stage within an environment."""
    if stage not in LIFECYCLE_STAGES:
        raise LifecycleError(f"Invalid stage '{stage}'.")
    results = []
    for name in vault.list_secrets(environment):
        entry = vault.get_secret(environment, name)
        if entry and entry.to_dict().get("lifecycle_stage", "active") == stage:
            results.append(name)
    return results
