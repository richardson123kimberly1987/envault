"""Secret rotation utilities for envault."""

from __future__ import annotations

import datetime
from typing import List, Optional

from envault.vault import Vault, VaultError


class RotationError(Exception):
    """Raised when a rotation operation fails."""


def rotate_secret(
    vault: Vault,
    key: str,
    new_value: str,
    environment: Optional[str] = None,
) -> dict:
    """Rotate a secret to a new value, preserving the old value as history.

    Returns a dict with 'key', 'environment', 'rotated_at', and 'previous_version'.
    Raises RotationError if the key does not exist.
    """
    env = environment or "default"
    entry = vault.get(key, environment=env)
    if entry is None:
        raise RotationError(
            f"Secret '{key}' not found in environment '{env}'. "
            "Cannot rotate a non-existent secret."
        )

    previous_version = entry.to_dict() if hasattr(entry, "to_dict") else {"value": entry}
    vault.set(key, new_value, environment=env)

    rotated_at = datetime.datetime.utcnow().isoformat() + "Z"
    return {
        "key": key,
        "environment": env,
        "rotated_at": rotated_at,
        "previous_version": previous_version,
    }


def rotate_all(
    vault: Vault,
    updates: dict,
    environment: Optional[str] = None,
) -> List[dict]:
    """Rotate multiple secrets at once.

    *updates* is a mapping of {key: new_value}.
    Returns a list of rotation result dicts (one per key).
    Keys that do not exist are skipped and reported with 'skipped': True.
    """
    results = []
    for key, new_value in updates.items():
        try:
            result = rotate_secret(vault, key, new_value, environment=environment)
            result["skipped"] = False
            results.append(result)
        except RotationError as exc:
            results.append(
                {
                    "key": key,
                    "environment": environment or "default",
                    "skipped": True,
                    "reason": str(exc),
                }
            )
    return results
