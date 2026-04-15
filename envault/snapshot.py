"""Snapshot and restore functionality for envault vaults."""
from __future__ import annotations

import json
import datetime
from typing import Any


class SnapshotError(Exception):
    """Raised when a snapshot operation fails."""


class Snapshot:
    """Represents a point-in-time snapshot of a vault's secrets."""

    def __init__(self, environment: str, data: dict[str, Any], created_at: str | None = None) -> None:
        self.environment = environment
        self.data = data
        self.created_at: str = created_at or datetime.datetime.utcnow().isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "environment": self.environment,
            "created_at": self.created_at,
            "data": self.data,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Snapshot":
        return cls(
            environment=d["environment"],
            data=d["data"],
            created_at=d.get("created_at"),
        )


def take_snapshot(vault: Any, environment: str) -> Snapshot:
    """Capture the current state of all secrets in *environment*."""
    secrets = vault.list_secrets(environment)
    if secrets is None:
        raise SnapshotError(f"Environment '{environment}' not found in vault.")
    data = {}
    for key in secrets:
        entry = vault.get_secret(environment, key)
        if entry is not None:
            data[key] = entry.to_dict()
    return Snapshot(environment=environment, data=data)


def save_snapshot(snapshot: Snapshot, path: str) -> None:
    """Persist *snapshot* to a JSON file at *path*."""
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(snapshot.to_dict(), fh, indent=2)
    except OSError as exc:
        raise SnapshotError(f"Failed to write snapshot: {exc}") from exc


def load_snapshot(path: str) -> Snapshot:
    """Load a snapshot from a JSON file at *path*."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise SnapshotError(f"Failed to read snapshot: {exc}") from exc
    return Snapshot.from_dict(raw)


def restore_snapshot(vault: Any, snapshot: Snapshot, passphrase: str) -> int:
    """Restore secrets from *snapshot* into *vault*, returning count of restored keys."""
    restored = 0
    for key, entry_dict in snapshot.data.items():
        value = entry_dict.get("value", "")
        vault.set_secret(snapshot.environment, key, value, passphrase)
        restored += 1
    vault.save(passphrase)
    return restored
