"""Prefix management for environment variable secrets."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


class PrefixError(Exception):
    """Raised when a prefix operation fails."""


@dataclass
class PrefixResult:
    secret: str
    environment: str
    old_name: str
    new_name: str
    action: str  # 'add' | 'remove'

    def to_dict(self) -> dict:
        return {
            "secret": self.secret,
            "environment": self.environment,
            "old_name": self.old_name,
            "new_name": self.new_name,
            "action": self.action,
        }


def _get_entry_or_raise(vault, environment: str, secret: str):
    entry = vault.get_secret(environment, secret)
    if entry is None:
        raise PrefixError(f"Secret '{secret}' not found in environment '{environment}'")
    return entry


def add_prefix(vault, environment: str, secret: str, prefix: str) -> PrefixResult:
    """Rename a secret by prepending *prefix* to its name."""
    if not prefix:
        raise PrefixError("Prefix must not be empty")
    _get_entry_or_raise(vault, environment, secret)
    new_name = f"{prefix}{secret}"
    if vault.get_secret(environment, new_name) is not None:
        raise PrefixError(
            f"A secret named '{new_name}' already exists in environment '{environment}'"
        )
    entry = vault.get_secret(environment, secret)
    vault.set_secret(environment, new_name, entry.decrypt())
    vault.delete_secret(environment, secret)
    return PrefixResult(
        secret=new_name,
        environment=environment,
        old_name=secret,
        new_name=new_name,
        action="add",
    )


def remove_prefix(vault, environment: str, secret: str, prefix: str) -> PrefixResult:
    """Rename a secret by stripping *prefix* from its name."""
    if not prefix:
        raise PrefixError("Prefix must not be empty")
    if not secret.startswith(prefix):
        raise PrefixError(f"Secret '{secret}' does not start with prefix '{prefix}'")
    _get_entry_or_raise(vault, environment, secret)
    new_name = secret[len(prefix):]
    if not new_name:
        raise PrefixError("Removing the prefix would result in an empty secret name")
    if vault.get_secret(environment, new_name) is not None:
        raise PrefixError(
            f"A secret named '{new_name}' already exists in environment '{environment}'"
        )
    entry = vault.get_secret(environment, secret)
    vault.set_secret(environment, new_name, entry.decrypt())
    vault.delete_secret(environment, secret)
    return PrefixResult(
        secret=new_name,
        environment=environment,
        old_name=secret,
        new_name=new_name,
        action="remove",
    )


def list_prefixed(vault, environment: str, prefix: str) -> List[str]:
    """Return all secret names in *environment* that start with *prefix*."""
    return [
        name
        for name in vault.list_secrets(environment)
        if name.startswith(prefix)
    ]
