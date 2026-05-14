"""Suffix management for secret keys in envault."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


class SuffixError(Exception):
    """Raised when a suffix operation fails."""


@dataclass
class SuffixResult:
    secret: str
    environment: str
    old_key: str
    new_key: str
    suffix: str
    removed: bool = False

    def to_dict(self) -> dict:
        return {
            "secret": self.secret,
            "environment": self.environment,
            "old_key": self.old_key,
            "new_key": self.new_key,
            "suffix": self.suffix,
            "removed": self.removed,
        }


def _get_entry_or_raise(vault, environment: str, secret: str):
    entry = vault.get_secret(environment, secret)
    if entry is None:
        raise SuffixError(f"Secret '{secret}' not found in environment '{environment}'")
    return entry


def add_suffix(vault, environment: str, secret: str, suffix: str) -> SuffixResult:
    """Rename a secret key by appending a suffix."""
    if not suffix:
        raise SuffixError("Suffix must not be empty")
    _get_entry_or_raise(vault, environment, secret)
    new_key = f"{secret}{suffix}"
    if vault.get_secret(environment, new_key) is not None:
        raise SuffixError(f"Secret '{new_key}' already exists in environment '{environment}'")
    entry = vault.get_secret(environment, secret)
    vault.set_secret(environment, new_key, entry.decrypt())
    vault.delete_secret(environment, secret)
    return SuffixResult(
        secret=new_key,
        environment=environment,
        old_key=secret,
        new_key=new_key,
        suffix=suffix,
        removed=False,
    )


def remove_suffix(vault, environment: str, secret: str, suffix: str) -> SuffixResult:
    """Rename a secret key by stripping a suffix."""
    if not suffix:
        raise SuffixError("Suffix must not be empty")
    if not secret.endswith(suffix):
        raise SuffixError(f"Secret '{secret}' does not end with suffix '{suffix}'")
    _get_entry_or_raise(vault, environment, secret)
    new_key = secret[: -len(suffix)]
    if not new_key:
        raise SuffixError("Removing suffix would result in an empty key")
    if vault.get_secret(environment, new_key) is not None:
        raise SuffixError(f"Secret '{new_key}' already exists in environment '{environment}'")
    entry = vault.get_secret(environment, secret)
    vault.set_secret(environment, new_key, entry.decrypt())
    vault.delete_secret(environment, secret)
    return SuffixResult(
        secret=new_key,
        environment=environment,
        old_key=secret,
        new_key=new_key,
        suffix=suffix,
        removed=True,
    )


def list_with_suffix(vault, environment: str, suffix: str) -> List[str]:
    """Return all secret keys in an environment that end with the given suffix."""
    return [
        s for s in vault.list_secrets(environment) if s.endswith(suffix)
    ]
