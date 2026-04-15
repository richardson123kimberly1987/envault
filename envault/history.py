"""Secret value history tracking for envault."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional


class HistoryError(Exception):
    """Raised when a history operation fails."""


@dataclass
class HistoryEntry:
    """A single historical record of a secret's value."""

    version: int
    encrypted_value: str
    updated_at: str
    updated_by: str

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "encrypted_value": self.encrypted_value,
            "updated_at": self.updated_at,
            "updated_by": self.updated_by,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "HistoryEntry":
        return cls(
            version=data["version"],
            encrypted_value=data["encrypted_value"],
            updated_at=data["updated_at"],
            updated_by=data["updated_by"],
        )


def record_history(
    vault,
    environment: str,
    key: str,
    updated_by: str = "cli",
) -> HistoryEntry:
    """Snapshot the current value of *key* into the vault's history store.

    The vault object is expected to expose:
      - ``get_secret(environment, key)`` -> entry with ``.to_dict()``
      - ``_data`` dict used to persist history under ``"_history"``
    """
    entry = vault.get_secret(environment, key)
    if entry is None:
        raise HistoryError(f"Secret '{key}' not found in environment '{environment}'.")

    history_store: dict = vault._data.setdefault("_history", {})
    env_store: dict = history_store.setdefault(environment, {})
    key_history: list = env_store.setdefault(key, [])

    version = len(key_history) + 1
    now = datetime.now(timezone.utc).isoformat()
    hist_entry = HistoryEntry(
        version=version,
        encrypted_value=entry.to_dict()["value"],
        updated_at=now,
        updated_by=updated_by,
    )
    key_history.append(hist_entry.to_dict())
    vault.save()
    return hist_entry


def get_history(
    vault,
    environment: str,
    key: str,
    limit: Optional[int] = None,
) -> List[HistoryEntry]:
    """Return the history list for *key* in *environment*, newest first."""
    history_store: dict = vault._data.get("_history", {})
    key_history: list = history_store.get(environment, {}).get(key, [])
    entries = [HistoryEntry.from_dict(e) for e in key_history]
    entries.sort(key=lambda e: e.version, reverse=True)
    if limit is not None:
        entries = entries[:limit]
    return entries
