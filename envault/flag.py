"""Feature-flag style boolean markers for secrets."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

FLAG_KEYS = ("enabled", "disabled", "beta", "deprecated", "internal", "public")


class FlagError(Exception):
    """Raised when a flag operation fails."""


@dataclass
class FlagResult:
    secret: str
    environment: str
    flags: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "secret": self.secret,
            "environment": self.environment,
            "flags": self.flags,
        }


def _get_entry_or_raise(vault, environment: str, secret: str):
    entry = vault.get_secret(environment, secret)
    if entry is None:
        raise FlagError(f"Secret '{secret}' not found in environment '{environment}'")
    return entry


def set_flag(vault, environment: str, secret: str, flag: str) -> FlagResult:
    """Add *flag* to the secret's metadata flags list."""
    if flag not in FLAG_KEYS:
        raise FlagError(f"Unknown flag '{flag}'. Valid flags: {list(FLAG_KEYS)}")
    entry = _get_entry_or_raise(vault, environment, secret)
    meta = entry.to_dict()
    flags: List[str] = list(meta.get("flags") or [])
    if flag not in flags:
        flags.append(flag)
    entry.update_value(meta.get("value", ""), extra={"flags": flags})
    vault.save()
    return FlagResult(secret=secret, environment=environment, flags=flags)


def unset_flag(vault, environment: str, secret: str, flag: str) -> FlagResult:
    """Remove *flag* from the secret's metadata flags list."""
    entry = _get_entry_or_raise(vault, environment, secret)
    meta = entry.to_dict()
    flags: List[str] = list(meta.get("flags") or [])
    if flag in flags:
        flags.remove(flag)
    entry.update_value(meta.get("value", ""), extra={"flags": flags})
    vault.save()
    return FlagResult(secret=secret, environment=environment, flags=flags)


def list_flags(vault, environment: str, secret: str) -> FlagResult:
    """Return current flags for *secret* in *environment*."""
    entry = _get_entry_or_raise(vault, environment, secret)
    meta = entry.to_dict()
    flags: List[str] = list(meta.get("flags") or [])
    return FlagResult(secret=secret, environment=environment, flags=flags)
