"""Secret locking — prevent accidental modification of critical secrets."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


class LockError(Exception):
    """Raised when a lock operation fails."""


@dataclass
class LockResult:
    key: str
    environment: str
    locked: bool
    message: str

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "environment": self.environment,
            "locked": self.locked,
            "message": self.message,
        }


def lock_secret(vault, environment: str, key: str) -> LockResult:
    """Mark a secret as locked, preventing modification."""
    entry = vault.get_secret(environment, key)
    if entry is None:
        raise LockError(f"Secret '{key}' not found in environment '{environment}'")

    data = entry.to_dict()
    if data.get("locked"):
        return LockResult(key=key, environment=environment, locked=True,
                          message=f"'{key}' is already locked")

    data["locked"] = True
    vault.set_secret(environment, key, data["value"], metadata=data)
    return LockResult(key=key, environment=environment, locked=True,
                      message=f"'{key}' locked successfully")


def unlock_secret(vault, environment: str, key: str) -> LockResult:
    """Remove the lock from a secret, allowing modification."""
    entry = vault.get_secret(environment, key)
    if entry is None:
        raise LockError(f"Secret '{key}' not found in environment '{environment}'")

    data = entry.to_dict()
    if not data.get("locked"):
        return LockResult(key=key, environment=environment, locked=False,
                          message=f"'{key}' is not locked")

    data["locked"] = False
    vault.set_secret(environment, key, data["value"], metadata=data)
    return LockResult(key=key, environment=environment, locked=False,
                      message=f"'{key}' unlocked successfully")


def list_locked(vault, environment: str) -> List[str]:
    """Return names of all locked secrets in an environment."""
    locked = []
    for key in vault.list_secrets(environment):
        entry = vault.get_secret(environment, key)
        if entry is not None and entry.to_dict().get("locked"):
            locked.append(key)
    return locked


def is_locked(vault, environment: str, key: str) -> bool:
    """Return True if the secret is currently locked."""
    entry = vault.get_secret(environment, key)
    if entry is None:
        return False
    return bool(entry.to_dict().get("locked", False))
