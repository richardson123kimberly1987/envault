"""Scope filtering — restrict secret visibility to named scopes (e.g. service names)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


class ScopeError(Exception):
    """Raised when a scope operation fails."""


@dataclass
class ScopeResult:
    secret: str
    environment: str
    scopes: List[str]
    action: str  # "added" | "removed" | "listed"

    def to_dict(self) -> dict:
        return {
            "secret": self.secret,
            "environment": self.environment,
            "scopes": self.scopes,
            "action": self.action,
        }


def _get_entry_or_raise(vault, environment: str, secret: str):
    """Fetch a secret entry from the vault, raising ScopeError if not found."""
    entry = vault.get_secret(environment, secret)
    if entry is None:
        raise ScopeError(f"Secret '{secret}' not found in environment '{environment}'")
    return entry


def add_scope(vault, environment: str, secret: str, scope: str) -> ScopeResult:
    """Add *scope* to the named secret's metadata."""
    entry = _get_entry_or_raise(vault, environment, secret)

    data = entry.to_dict()
    scopes: List[str] = data.get("scopes") or []
    if scope not in scopes:
        scopes.append(scope)
    data["scopes"] = scopes

    vault.set_secret(environment, secret, data["value"], metadata=data)
    vault.save()
    return ScopeResult(secret=secret, environment=environment, scopes=scopes, action="added")


def remove_scope(vault, environment: str, secret: str, scope: str) -> ScopeResult:
    """Remove *scope* from the named secret's metadata."""
    entry = _get_entry_or_raise(vault, environment, secret)

    data = entry.to_dict()
    scopes: List[str] = data.get("scopes") or []
    if scope not in scopes:
        raise ScopeError(f"Scope '{scope}' is not assigned to '{secret}'")
    scopes.remove(scope)
    data["scopes"] = scopes

    vault.set_secret(environment, secret, data["value"], metadata=data)
    vault.save()
    return ScopeResult(secret=secret, environment=environment, scopes=scopes, action="removed")


def list_scopes(vault, environment: str, secret: str) -> ScopeResult:
    """Return the scopes currently assigned to a secret."""
    entry = _get_entry_or_raise(vault, environment, secret)

    scopes: List[str] = (entry.to_dict().get("scopes") or [])
    return ScopeResult(secret=secret, environment=environment, scopes=scopes, action="listed")


def filter_by_scope(
    vault, environment: str, scope: str
) -> List[str]:
    """Return names of secrets in *environment* that carry *scope*."""
    matched = []
    for name in vault.list_secrets(environment):
        entry = vault.get_secret(environment, name)
        if entry is None:
            continue
        if scope in (entry.to_dict().get("scopes") or []):
            matched.append(name)
    return matched
