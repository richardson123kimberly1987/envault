"""Clone secrets from one environment to another."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


class CloneError(Exception):
    """Raised when cloning fails."""


@dataclass
class CloneResult:
    source_env: str
    target_env: str
    cloned: List[str]
    skipped: List[str]

    def to_dict(self) -> dict:
        return {
            "source_env": self.source_env,
            "target_env": self.target_env,
            "cloned": self.cloned,
            "skipped": self.skipped,
        }


def clone_environment(
    vault,
    source_env: str,
    target_env: str,
    overwrite: bool = False,
    keys: Optional[List[str]] = None,
) -> CloneResult:
    """Copy secrets from *source_env* into *target_env*.

    Args:
        vault: A Vault instance.
        source_env: Name of the environment to copy from.
        target_env: Name of the environment to copy into.
        overwrite: When False, existing secrets in target are skipped.
        keys: Optional list of secret keys to clone; clones all if None.

    Returns:
        A CloneResult describing what was cloned and what was skipped.

    Raises:
        CloneError: If source_env does not exist or source == target.
    """
    if source_env == target_env:
        raise CloneError("Source and target environments must differ.")

    available = vault.list_environments()
    if source_env not in available:
        raise CloneError(f"Source environment '{source_env}' does not exist.")

    all_keys = vault.list_secrets(source_env)
    if keys is not None:
        missing = [k for k in keys if k not in all_keys]
        if missing:
            raise CloneError(
                f"Keys not found in '{source_env}': {', '.join(missing)}"
            )
        all_keys = keys

    cloned: List[str] = []
    skipped: List[str] = []

    for key in all_keys:
        existing = vault.get_secret(target_env, key)
        if existing is not None and not overwrite:
            skipped.append(key)
            continue
        entry = vault.get_secret(source_env, key)
        if entry is None:
            skipped.append(key)
            continue
        vault.set_secret(target_env, key, entry.value)
        cloned.append(key)

    return CloneResult(
        source_env=source_env,
        target_env=target_env,
        cloned=cloned,
        skipped=skipped,
    )
