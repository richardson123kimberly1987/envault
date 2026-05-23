"""Pivot module: reorganize secrets by swapping key/value axes across environments."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


class PivotError(Exception):
    """Raised when a pivot operation fails."""


@dataclass
class PivotEntry:
    value: str
    environments: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"value": self.value, "environments": self.environments}


@dataclass
class PivotResult:
    environment: str
    pivoted: Dict[str, PivotEntry] = field(default_factory=dict)
    total: int = 0

    def to_dict(self) -> dict:
        return {
            "environment": self.environment,
            "pivoted": {k: v.to_dict() for k, v in self.pivoted.items()},
            "total": self.total,
        }


def pivot_environment(vault, environment: str, target_env: Optional[str] = None) -> PivotResult:
    """Pivot secrets in *environment* grouping keys by their decrypted value.

    If *target_env* is given, only secrets that also exist in *target_env*
    with the same value are included.
    """
    secrets = vault.list_secrets(environment)
    if not secrets:
        raise PivotError(f"No secrets found in environment '{environment}'")

    pivoted: Dict[str, PivotEntry] = {}

    for key in secrets:
        entry = vault.get_secret(environment, key)
        if entry is None:
            continue
        try:
            value = entry.decrypt()
        except Exception as exc:  # noqa: BLE001
            raise PivotError(f"Failed to decrypt '{key}': {exc}") from exc

        envs = [environment]
        if target_env:
            other = vault.get_secret(target_env, key)
            if other is None:
                continue
            try:
                other_value = other.decrypt()
            except Exception as exc:  # noqa: BLE001
                raise PivotError(f"Failed to decrypt '{key}' in '{target_env}': {exc}") from exc
            if other_value != value:
                continue
            envs.append(target_env)

        if value not in pivoted:
            pivoted[value] = PivotEntry(value=value, environments=envs)
        else:
            for env in envs:
                if env not in pivoted[value].environments:
                    pivoted[value].environments.append(env)

    return PivotResult(environment=environment, pivoted=pivoted, total=len(pivoted))
