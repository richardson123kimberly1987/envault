"""Replay module: re-apply a sequence of audit events to reconstruct secret state."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from envault.audit import AuditLog, AuditEvent


class ReplayError(Exception):
    """Raised when replay encounters an unrecoverable problem."""


@dataclass
class ReplayResult:
    replayed: int
    skipped: int
    events: List[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "replayed": self.replayed,
            "skipped": self.skipped,
            "events": self.events,
        }


def replay_events(
    audit_log: AuditLog,
    vault,
    *,
    environment: Optional[str] = None,
    action_filter: Optional[str] = None,
    dry_run: bool = False,
) -> ReplayResult:
    """Re-apply SET events from the audit log to the vault.

    Only events whose action is ``set`` (or matches *action_filter*) and whose
    environment matches *environment* (when supplied) are replayed.
    """
    target_action = action_filter or "set"
    replayed = 0
    skipped = 0
    applied: List[dict] = []

    events: List[AuditEvent] = audit_log.load()

    for event in events:
        if event.action != target_action:
            skipped += 1
            continue

        meta = event.metadata or {}
        env = meta.get("environment")
        key = meta.get("key")
        value = meta.get("value")

        if environment is not None and env != environment:
            skipped += 1
            continue

        if not key or value is None:
            skipped += 1
            continue

        if not dry_run:
            try:
                vault.set_secret(env or "default", key, value)
            except Exception as exc:  # pragma: no cover
                raise ReplayError(f"Failed to replay event for key '{key}': {exc}") from exc

        replayed += 1
        applied.append(event.to_dict())

    return ReplayResult(replayed=replayed, skipped=skipped, events=applied)
