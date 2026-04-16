"""Promote secrets from one environment to another."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional


class PromoteError(Exception):
    """Raised when promotion fails."""


@dataclass
class PromoteResult:
    source: str
    destination: str
    promoted: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)
    overwritten: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "destination": self.destination,
            "promoted": self.promoted,
            "skipped": self.skipped,
            "overwritten": self.overwritten,
        }


def promote_environment(
    vault,
    source: str,
    destination: str,
    keys: Optional[List[str]] = None,
    overwrite: bool = False,
    dry_run: bool = False,
) -> PromoteResult:
    """Copy secrets from *source* env into *destination* env."""
    src_secrets = vault.list_secrets(source)
    if not src_secrets:
        raise PromoteError(f"Source environment '{source}' has no secrets.")

    targets = keys if keys is not None else src_secrets
    unknown = set(targets) - set(src_secrets)
    if unknown:
        raise PromoteError(f"Keys not found in source: {sorted(unknown)}")

    result = PromoteResult(source=source, destination=destination)

    for key in targets:
        entry = vault.get_secret(source, key)
        existing = vault.get_secret(destination, key)
        if existing is not None:
            if not overwrite:
                result.skipped.append(key)
                continue
            result.overwritten.append(key)
        else:
            result.promoted.append(key)

        if not dry_run:
            vault.set_secret(destination, key, entry.value if hasattr(entry, 'value') else entry)

    return result
