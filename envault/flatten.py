"""Flatten nested environment secrets into a single environment."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


class FlattenError(Exception):
    """Raised when flattening fails."""


@dataclass
class FlattenResult:
    source_envs: List[str]
    target_env: str
    keys_merged: List[str]
    keys_skipped: List[str]
    overwrite: bool

    def to_dict(self) -> dict:
        return {
            "source_envs": self.source_envs,
            "target_env": self.target_env,
            "keys_merged": self.keys_merged,
            "keys_skipped": self.keys_skipped,
            "overwrite": self.overwrite,
        }


def flatten_environments(
    vault,
    source_envs: List[str],
    target_env: str,
    overwrite: bool = False,
) -> FlattenResult:
    """Merge secrets from multiple source environments into target_env.

    Keys appearing in earlier source environments take precedence unless
    *overwrite* is True, in which case later sources overwrite earlier ones.

    Args:
        vault: Vault instance with get_secret / set_secret / list_secrets.
        source_envs: Ordered list of environment names to flatten.
        target_env: Destination environment name.
        overwrite: When True, later sources overwrite earlier ones.

    Returns:
        FlattenResult summarising the operation.

    Raises:
        FlattenError: If source_envs is empty or target_env is blank.
    """
    if not source_envs:
        raise FlattenError("source_envs must not be empty")
    if not target_env or not target_env.strip():
        raise FlattenError("target_env must not be blank")

    merged: Dict[str, object] = {}
    keys_skipped: List[str] = []

    for env in source_envs:
        for key in vault.list_secrets(env):
            entry = vault.get_secret(env, key)
            if entry is None:
                continue
            if key in merged and not overwrite:
                keys_skipped.append(key)
                continue
            merged[key] = entry

    for key, entry in merged.items():
        vault.set_secret(target_env, key, entry.decrypt())

    return FlattenResult(
        source_envs=list(source_envs),
        target_env=target_env,
        keys_merged=list(merged.keys()),
        keys_skipped=keys_skipped,
        overwrite=overwrite,
    )
