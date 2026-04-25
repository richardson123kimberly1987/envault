"""Cascade: propagate secret values from a source environment to target environments."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


class CascadeError(Exception):
    """Raised when a cascade operation fails."""


@dataclass
class CascadeResult:
    source_env: str
    target_envs: List[str]
    secret_name: str
    propagated_to: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)
    overwrite: bool = False

    def to_dict(self) -> dict:
        return {
            "source_env": self.source_env,
            "target_envs": self.target_envs,
            "secret_name": self.secret_name,
            "propagated_to": self.propagated_to,
            "skipped": self.skipped,
            "overwrite": self.overwrite,
        }


def cascade_secret(
    vault,
    secret_name: str,
    source_env: str,
    target_envs: List[str],
    overwrite: bool = False,
) -> CascadeResult:
    """Copy *secret_name* from *source_env* into each of *target_envs*.

    If *overwrite* is False (default) and the secret already exists in a
    target environment it is added to *skipped* rather than overwritten.
    """
    source_entry = vault.get_secret(secret_name, source_env)
    if source_entry is None:
        raise CascadeError(
            f"Secret '{secret_name}' not found in environment '{source_env}'."
        )

    result = CascadeResult(
        source_env=source_env,
        target_envs=list(target_envs),
        secret_name=secret_name,
        overwrite=overwrite,
    )

    source_data = source_entry.to_dict()
    value = source_data.get("value", "")

    for env in target_envs:
        existing = vault.get_secret(secret_name, env)
        if existing is not None and not overwrite:
            result.skipped.append(env)
            continue
        vault.set_secret(secret_name, value, env)
        result.propagated_to.append(env)

    return result


def cascade_all(
    vault,
    source_env: str,
    target_envs: List[str],
    overwrite: bool = False,
) -> List[CascadeResult]:
    """Cascade every secret in *source_env* to all *target_envs*."""
    secrets = vault.list_secrets(source_env)
    return [
        cascade_secret(vault, name, source_env, target_envs, overwrite=overwrite)
        for name in secrets
    ]
