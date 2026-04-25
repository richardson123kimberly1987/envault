"""Secret status reporting for envault."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

STATUS_FIELDS = ("locked", "pinned", "deprecated", "archived", "expiry", "ttl")


class StatusError(Exception):
    """Raised when status reporting fails."""


@dataclass
class SecretStatus:
    key: str
    environment: str
    locked: bool = False
    pinned: bool = False
    deprecated: bool = False
    archived: bool = False
    expiry: str | None = None
    ttl: int | None = None
    scopes: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    created_at: str | None = None
    updated_at: str | None = None

    @property
    def is_expired(self) -> bool:
        if not self.expiry:
            return False
        try:
            exp = datetime.fromisoformat(self.expiry)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            return datetime.now(tz=timezone.utc) > exp
        except ValueError:
            return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "environment": self.environment,
            "locked": self.locked,
            "pinned": self.pinned,
            "deprecated": self.deprecated,
            "archived": self.archived,
            "expiry": self.expiry,
            "ttl": self.ttl,
            "scopes": self.scopes,
            "tags": self.tags,
            "is_expired": self.is_expired,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


def get_status(vault: Any, key: str, environment: str) -> SecretStatus:
    """Return a status summary for a secret in a given environment."""
    entry = vault.get_secret(key, environment)
    if entry is None:
        raise StatusError(f"Secret '{key}' not found in environment '{environment}'")

    raw = entry.to_dict()
    return SecretStatus(
        key=key,
        environment=environment,
        locked=bool(raw.get("locked", False)),
        pinned=bool(raw.get("pinned", False)),
        deprecated=bool(raw.get("deprecated", False)),
        archived=bool(raw.get("archived", False)),
        expiry=raw.get("expiry"),
        ttl=raw.get("ttl"),
        scopes=list(raw.get("scopes") or []),
        tags=list(raw.get("tags") or []),
        created_at=raw.get("created_at"),
        updated_at=raw.get("updated_at"),
    )


def get_all_statuses(vault: Any, environment: str) -> list[SecretStatus]:
    """Return status summaries for every secret in an environment."""
    keys = vault.list_secrets(environment)
    return [get_status(vault, k, environment) for k in keys]
