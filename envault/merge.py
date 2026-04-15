"""Merge secrets from one environment into another."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


class MergeError(Exception):
    """Raised when a merge operation fails."""


@dataclass
class MergeResult:
    source_env: str
    target_env: str
    merged: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)
    overwritten: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "source_env": self.source_env,
            "target_env": self.target_env,
            "merged": self.merged,
            "skipped": self.skipped,
            "overwritten": self.overwritten,
        }


def merge_environments(
    vault,
    source_env: str,
    target_env: str,
    overwrite: bool = False,
    keys: Optional[List[str]] = None,
) -> MergeResult:
    """Merge secrets from *source_env* into *target_env*.

    Args:
        vault: A Vault instance.
        source_env: Name of the environment to read secrets from.
        target_env: Name of the environment to write secrets into.
        overwrite: If True, existing secrets in target are overwritten.
        keys: Optional list of secret keys to merge; merges all if None.

    Returns:
        A MergeResult describing what happened.

    Raises:
        MergeError: If source or target environment is invalid.
    """
    available = vault.list_environments()

    if source_env not in available:
        raise MergeError(f"Source environment '{source_env}' does not exist.")
    if target_env not in available:
        raise MergeError(f"Target environment '{target_env}' does not exist.")
    if source_env == target_env:
        raise MergeError("Source and target environments must be different.")

    result = MergeResult(source_env=source_env, target_env=target_env)

    source_keys = vault.list_secrets(source_env)
    if keys is not None:
        missing = set(keys) - set(source_keys)
        if missing:
            raise MergeError(
                f"Keys not found in source environment: {sorted(missing)}"
            )
        source_keys = [k for k in source_keys if k in keys]

    target_keys = set(vault.list_secrets(target_env))

    for key in source_keys:
        entry = vault.get_secret(source_env, key)
        if entry is None:
            continue
        if key in target_keys:
            if overwrite:
                vault.set_secret(target_env, key, entry.value)
                result.overwritten.append(key)
            else:
                result.skipped.append(key)
        else:
            vault.set_secret(target_env, key, entry.value)
            result.merged.append(key)

    return result
