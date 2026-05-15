"""squeeze.py – remove redundant/whitespace-only secrets from a vault environment."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


class SqueezeError(Exception):
    """Raised when a squeeze operation fails."""


@dataclass
class SqueezeResult:
    environment: str
    removed: List[str] = field(default_factory=list)
    kept: int = 0
    dry_run: bool = False

    def to_dict(self) -> dict:
        return {
            "environment": self.environment,
            "removed": self.removed,
            "kept": self.kept,
            "dry_run": self.dry_run,
        }


def _is_blank(value: str) -> bool:
    """Return True if *value* is empty or contains only whitespace."""
    return value.strip() == ""


def squeeze_environment(
    vault,
    environment: str,
    dry_run: bool = False,
) -> SqueezeResult:
    """Remove secrets whose decrypted value is blank from *environment*.

    Parameters
    ----------
    vault:
        A :class:`~envault.vault.Vault` instance.
    environment:
        Target environment name.
    dry_run:
        When *True* the vault is not mutated; only the result is computed.

    Returns
    -------
    SqueezeResult
    """
    names = vault.list_secrets(environment)
    if names is None:
        raise SqueezeError(f"Environment '{environment}' not found.")

    result = SqueezeResult(environment=environment, dry_run=dry_run)

    for name in names:
        entry = vault.get_secret(environment, name)
        if entry is None:
            continue
        try:
            value: str = entry.decrypt()
        except Exception as exc:  # noqa: BLE001
            raise SqueezeError(
                f"Could not decrypt '{name}' in '{environment}': {exc}"
            ) from exc

        if _is_blank(value):
            result.removed.append(name)
            if not dry_run:
                vault.delete_secret(environment, name)
        else:
            result.kept += 1

    if not dry_run and result.removed:
        vault.save()

    return result
