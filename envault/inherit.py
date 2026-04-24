"""Secret inheritance: propagate secrets from a base environment to child environments."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


class InheritError(Exception):
    """Raised when an inheritance operation fails."""


@dataclass
class InheritResult:
    base_env: str
    target_env: str
    inherited: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)
    overwrite: bool = False

    def to_dict(self) -> dict:
        return {
            "base_env": self.base_env,
            "target_env": self.target_env,
            "inherited": self.inherited,
            "skipped": self.skipped,
            "overwrite": self.overwrite,
        }


def inherit_environment(
    vault,
    base_env: str,
    target_env: str,
    overwrite: bool = False,
    keys: Optional[List[str]] = None,
) -> InheritResult:
    """Copy secrets from *base_env* into *target_env*.

    Args:
        vault: A Vault instance.
        base_env: Name of the source environment.
        target_env: Name of the destination environment.
        overwrite: If True, existing secrets in target_env are overwritten.
        keys: Optional allowlist of secret names to inherit; None means all.

    Returns:
        InheritResult summarising what was inherited and what was skipped.
    """
    if base_env not in vault.list_environments():
        raise InheritError(f"Base environment '{base_env}' does not exist.")
    if target_env == base_env:
        raise InheritError("Base and target environments must be different.")

    result = InheritResult(
        base_env=base_env,
        target_env=target_env,
        overwrite=overwrite,
    )

    source_keys = vault.list_secrets(base_env)
    if keys is not None:
        missing = set(keys) - set(source_keys)
        if missing:
            raise InheritError(
                f"Keys not found in '{base_env}': {', '.join(sorted(missing))}"
            )
        source_keys = [k for k in source_keys if k in keys]

    for key in source_keys:
        existing = vault.get_secret(target_env, key)
        if existing is not None and not overwrite:
            result.skipped.append(key)
            continue
        entry = vault.get_secret(base_env, key)
        vault.set_secret(target_env, key, entry.value)
        result.inherited.append(key)

    vault.save()
    return result
