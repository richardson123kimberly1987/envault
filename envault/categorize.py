"""Categorize secrets by type or custom category label."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

CATEGORIES = ["database", "api_key", "certificate", "token", "password", "other"]


class CategorizeError(Exception):
    """Raised when a categorization operation fails."""


@dataclass
class CategorizeResult:
    secret: str
    environment: str
    category: str
    previous: Optional[str]

    def to_dict(self) -> dict:
        return {
            "secret": self.secret,
            "environment": self.environment,
            "category": self.category,
            "previous": self.previous,
        }


def _get_entry_or_raise(vault, environment: str, secret: str):
    entry = vault.get_secret(environment, secret)
    if entry is None:
        raise CategorizeError(
            f"Secret '{secret}' not found in environment '{environment}'."
        )
    return entry


def set_category(vault, environment: str, secret: str, category: str) -> CategorizeResult:
    """Assign a category to a secret."""
    if category not in CATEGORIES:
        raise CategorizeError(
            f"Invalid category '{category}'. Choose from: {', '.join(CATEGORIES)}."
        )
    entry = _get_entry_or_raise(vault, environment, secret)
    data = entry.to_dict()
    previous = data.get("category")
    data["category"] = category
    entry.update_value(data.get("value", ""), extra=data)
    vault.set_secret(environment, secret, entry)
    return CategorizeResult(
        secret=secret, environment=environment, category=category, previous=previous
    )


def list_by_category(
    vault, environment: str, category: Optional[str] = None
) -> List[dict]:
    """List secrets filtered by category, or all with their categories."""
    results = []
    for sec in vault.list_secrets(environment):
        entry = vault.get_secret(environment, sec)
        if entry is None:
            continue
        data = entry.to_dict()
        cat = data.get("category", "other")
        if category is None or cat == category:
            results.append({"secret": sec, "environment": environment, "category": cat})
    return results
