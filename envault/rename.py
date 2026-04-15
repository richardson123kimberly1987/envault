"""Rename secrets across environments in a vault."""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


class RenameError(Exception):
    """Raised when a rename operation fails."""


@dataclass
class RenameResult:
    old_name: str
    new_name: str
    environments_updated: List[str]
    skipped_environments: List[str]

    def to_dict(self) -> dict:
        return {
            "old_name": self.old_name,
            "new_name": self.new_name,
            "environments_updated": self.environments_updated,
            "skipped_environments": self.skipped_environments,
        }


def rename_secret(
    vault,
    old_name: str,
    new_name: str,
    env: Optional[str] = None,
) -> RenameResult:
    """Rename a secret key, optionally scoped to a single environment.

    Args:
        vault: Vault instance.
        old_name: Existing secret name.
        new_name: Desired new secret name.
        env: If provided, only rename within that environment.

    Returns:
        RenameResult summarising what was changed.

    Raises:
        RenameError: If old_name is not found in any targeted environment,
                     or if new_name already exists in a targeted environment.
    """
    if not old_name or not old_name.strip():
        raise RenameError("old_name must not be empty")
    if not new_name or not new_name.strip():
        raise RenameError("new_name must not be empty")
    if old_name == new_name:
        raise RenameError("old_name and new_name are identical")

    environments = [env] if env else vault.list_environments()

    updated: List[str] = []
    skipped: List[str] = []

    for environment in environments:
        entry = vault.get_secret(environment, old_name)
        if entry is None:
            skipped.append(environment)
            continue
        if vault.get_secret(environment, new_name) is not None:
            raise RenameError(
                f"Secret '{new_name}' already exists in environment '{environment}'"
            )
        data = entry.to_dict()
        data["name"] = new_name
        vault.set_secret(environment, new_name, data["value"])
        vault.delete_secret(environment, old_name)
        updated.append(environment)

    if not updated:
        raise RenameError(
            f"Secret '{old_name}' not found in any targeted environment"
        )

    return RenameResult(
        old_name=old_name,
        new_name=new_name,
        environments_updated=updated,
        skipped_environments=skipped,
    )
