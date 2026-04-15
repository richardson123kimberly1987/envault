"""Audit log for tracking secret access and mutations."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional


AUDIT_EVENTS = ("set", "get", "delete", "rotate", "export")


@dataclass
class AuditEvent:
    event: str
    key: str
    environment: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    actor: str = field(default_factory=lambda: os.environ.get("USER", "unknown"))
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "event": self.event,
            "key": self.key,
            "environment": self.environment,
            "timestamp": self.timestamp,
            "actor": self.actor,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AuditEvent":
        return cls(
            event=data["event"],
            key=data["key"],
            environment=data["environment"],
            timestamp=data["timestamp"],
            actor=data.get("actor", "unknown"),
            metadata=data.get("metadata", {}),
        )


class AuditLog:
    def __init__(self, log_path: Path) -> None:
        self.log_path = Path(log_path)

    def record(self, event: str, key: str, environment: str, **metadata) -> AuditEvent:
        if event not in AUDIT_EVENTS:
            raise ValueError(f"Unknown audit event '{event}'. Must be one of {AUDIT_EVENTS}")
        entry = AuditEvent(event=event, key=key, environment=environment, metadata=metadata)
        self._append(entry)
        return entry

    def _append(self, entry: AuditEvent) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry.to_dict()) + "\n")

    def read(self, environment: Optional[str] = None, event: Optional[str] = None) -> List[AuditEvent]:
        if not self.log_path.exists():
            return []
        events: List[AuditEvent] = []
        with self.log_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                entry = AuditEvent.from_dict(json.loads(line))
                if environment and entry.environment != environment:
                    continue
                if event and entry.event != event:
                    continue
                events.append(entry)
        return events

    def clear(self) -> None:
        if self.log_path.exists():
            self.log_path.unlink()
