"""Data models for envault secrets and environments."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional


@dataclass
class SecretEntry:
    """Represents a single secret key-value pair with metadata."""

    key: str
    value: str
    created_at: str = field(default_factory=lambda: _utcnow_iso())
    updated_at: str = field(default_factory=lambda: _utcnow_iso())
    description: Optional[str] = None

    def update_value(self, new_value: str) -> None:
        """Update the secret value and refresh the updated_at timestamp."""
        self.value = new_value
        self.updated_at = _utcnow_iso()

    def to_dict(self) -> Dict:
        return {
            "key": self.key,
            "value": self.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> SecretEntry:
        return cls(
            key=data["key"],
            value=data["value"],
            created_at=data.get("created_at", _utcnow_iso()),
            updated_at=data.get("updated_at", _utcnow_iso()),
            description=data.get("description"),
        )


@dataclass
class Environment:
    """Represents a named environment holding multiple secrets."""

    name: str
    secrets: Dict[str, SecretEntry] = field(default_factory=dict)

    def set_secret(self, key: str, value: str, description: Optional[str] = None) -> None:
        if key in self.secrets:
            self.secrets[key].update_value(value)
            if description is not None:
                self.secrets[key].description = description
        else:
            self.secrets[key] = SecretEntry(key=key, value=value, description=description)

    def get_secret(self, key: str) -> Optional[SecretEntry]:
        return self.secrets.get(key)

    def delete_secret(self, key: str) -> bool:
        if key in self.secrets:
            del self.secrets[key]
            return True
        return False

    def keys(self) -> List[str]:
        return list(self.secrets.keys())

    def to_dict(self) -> Dict:
        return {k: v.to_dict() for k, v in self.secrets.items()}

    @classmethod
    def from_dict(cls, name: str, data: Dict) -> Environment:
        secrets = {k: SecretEntry.from_dict(v) for k, v in data.items()}
        return cls(name=name, secrets=secrets)


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
