"""Prune expired or stale secrets from a vault environment."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

PRUNE_STRATEGIES = ("expired", "stale", "all")


class PruneError(Exception):
    """Raised when pruning fails."""


@dataclass
class PruneResult:
    environment: str
    removed: List[str] = field(default_factory=list)
    dry_run: bool = False

    def to_dict(self) -> dict:
        return {
            "environment": self.environment,
            "removed": self.removed,
            "dry_run": self.dry_run,
        }


def _is_expired(entry) -> bool:
    expiry = entry.to_dict().get("expires_at")
    if not expiry:
        return False
    try:
        dt = datetime.fromisoformat(expiry)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt < datetime.now(timezone.utc)
    except (ValueError, TypeError):
        return False


def _is_stale(entry, stale_days: int = 90) -> bool:
    updated = entry.to_dict().get("updated_at")
    if not updated:
        return False
    try:
        dt = datetime.fromisoformat(updated)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - dt
        return delta.days >= stale_days
    except (ValueError, TypeError):
        return False


def prune_environment(
    vault,
    environment: str,
    strategy: str = "expired",
    stale_days: int = 90,
    dry_run: bool = False,
) -> PruneResult:
    """Remove secrets matching *strategy* from *environment*.

    Parameters
    ----------
    vault:      Vault instance.
    environment: Target environment name.
    strategy:   One of ``"expired"``, ``"stale"``, or ``"all"``.
    stale_days: Days without update to consider a secret stale.
    dry_run:    If *True*, report but do not delete.
    """
    if strategy not in PRUNE_STRATEGIES:
        raise PruneError(
            f"Unknown strategy {strategy!r}. Choose from {PRUNE_STRATEGIES}."
        )

    names: List[str] = vault.list_secrets(environment)
    removed: List[str] = []

    for name in names:
        entry = vault.get_secret(environment, name)
        if entry is None:
            continue
        should_remove = (
            (strategy == "expired" and _is_expired(entry))
            or (strategy == "stale" and _is_stale(entry, stale_days))
            or (
                strategy == "all"
                and (_is_expired(entry) or _is_stale(entry, stale_days))
            )
        )
        if should_remove:
            removed.append(name)
            if not dry_run:
                vault.delete_secret(environment, name)

    if not dry_run and removed:
        vault.save()

    return PruneResult(environment=environment, removed=removed, dry_run=dry_run)
