"""Archive and restore deleted secrets."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

ARCHIVE_KEY = "__archive__"


class ArchiveError(Exception):
    pass


@dataclass
class ArchiveEntry:
    environment: str
    key: str
    secret_dict: dict[str, Any]
    archived_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "environment": self.environment,
            "key": self.key,
            "secret": self.secret_dict,
            "archived_at": self.archived_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ArchiveEntry":
        return cls(
            environment=data["environment"],
            key=data["key"],
            secret_dict=data["secret"],
            archived_at=data["archived_at"],
        )


def archive_secret(vault: Any, environment: str, key: str) -> ArchiveEntry:
    """Move a secret to the archive and remove it from the vault."""
    entry = vault.get_secret(environment, key)
    if entry is None:
        raise ArchiveError(f"Secret '{key}' not found in environment '{environment}'.")

    meta = vault.load() if hasattr(vault, "load") else {}
    raw = vault._data if hasattr(vault, "_data") else {}
    archive: list[dict] = raw.get(ARCHIVE_KEY, [])

    ae = ArchiveEntry(environment=environment, key=key, secret_dict=entry.to_dict())
    archive.append(ae.to_dict())

    vault.delete_secret(environment, key)
    vault.set_raw(ARCHIVE_KEY, archive)
    return ae


def restore_secret(vault: Any, environment: str, key: str) -> ArchiveEntry:
    """Restore the most recently archived entry for key/environment."""
    raw = vault._data if hasattr(vault, "_data") else {}
    archive: list[dict] = raw.get(ARCHIVE_KEY, [])

    matches = [
        (i, ArchiveEntry.from_dict(e))
        for i, e in enumerate(archive)
        if e["environment"] == environment and e["key"] == key
    ]
    if not matches:
        raise ArchiveError(f"No archived entry for '{key}' in '{environment}'.")

    idx, ae = max(matches, key=lambda t: t[1].archived_at)
    archive.pop(idx)
    vault.set_raw(ARCHIVE_KEY, archive)
    vault.set_secret_from_dict(environment, key, ae.secret_dict)
    return ae


def list_archive(vault: Any) -> list[ArchiveEntry]:
    """Return all archived entries."""
    raw = vault._data if hasattr(vault, "_data") else {}
    return [ArchiveEntry.from_dict(e) for e in raw.get(ARCHIVE_KEY, [])]
