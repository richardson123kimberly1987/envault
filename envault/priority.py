"""Priority management for secrets — assign and query priority levels."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

PRIORITY_LEVELS: list[str] = ["low", "medium", "high", "critical"]


class PriorityError(Exception):
    """Raised when a priority operation fails."""


@dataclass
class PriorityResult:
    key: str
    environment: str
    priority: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "environment": self.environment,
            "priority": self.priority,
        }


def set_priority(vault: Any, environment: str, key: str, priority: str) -> PriorityResult:
    """Set the priority level for a secret."""
    if priority not in PRIORITY_LEVELS:
        raise PriorityError(
            f"Invalid priority {priority!r}. Choose from: {', '.join(PRIORITY_LEVELS)}"
        )
    entry = vault.get_secret(environment, key)
    if entry is None:
        raise PriorityError(f"Secret {key!r} not found in environment {environment!r}")
    data = entry.to_dict()
    data.setdefault("metadata", {})
    data["metadata"]["priority"] = priority
    vault.set_secret(environment, key, data["value"], data["metadata"])
    return PriorityResult(key=key, environment=environment, priority=priority)


def get_priority(vault: Any, environment: str, key: str) -> PriorityResult:
    """Get the priority level for a secret, defaulting to 'medium'."""
    entry = vault.get_secret(environment, key)
    if entry is None:
        raise PriorityError(f"Secret {key!r} not found in environment {environment!r}")
    data = entry.to_dict()
    priority = data.get("metadata", {}).get("priority", "medium")
    return PriorityResult(key=key, environment=environment, priority=priority)


def list_by_priority(vault: Any, environment: str, priority: str) -> list[PriorityResult]:
    """Return all secrets in an environment matching the given priority."""
    if priority not in PRIORITY_LEVELS:
        raise PriorityError(
            f"Invalid priority {priority!r}. Choose from: {', '.join(PRIORITY_LEVELS)}"
        )
    results: list[PriorityResult] = []
    for key in vault.list_secrets(environment):
        entry = vault.get_secret(environment, key)
        if entry is None:
            continue
        data = entry.to_dict()
        entry_priority = data.get("metadata", {}).get("priority", "medium")
        if entry_priority == priority:
            results.append(PriorityResult(key=key, environment=environment, priority=priority))
    return results
