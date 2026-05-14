"""Secret classification module for envault."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

CLASSIFICATION_LEVELS = ["public", "internal", "confidential", "restricted"]


class ClassifyError(Exception):
    """Raised when a classification operation fails."""


@dataclass
class ClassifyResult:
    secret: str
    environment: str
    level: str
    previous: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "secret": self.secret,
            "environment": self.environment,
            "level": self.level,
            "previous": self.previous,
        }


def _get_entry_or_raise(vault, environment: str, secret: str):
    entry = vault.get_secret(environment, secret)
    if entry is None:
        raise ClassifyError(
            f"Secret '{secret}' not found in environment '{environment}'"
        )
    return entry


def set_classification(vault, environment: str, secret: str, level: str) -> ClassifyResult:
    """Set the classification level of a secret."""
    if level not in CLASSIFICATION_LEVELS:
        raise ClassifyError(
            f"Invalid classification level '{level}'. "
            f"Choose from: {', '.join(CLASSIFICATION_LEVELS)}"
        )
    entry = _get_entry_or_raise(vault, environment, secret)
    data = entry.to_dict()
    previous = data.get("classification")
    data["classification"] = level
    entry.update_value(data.get("value", ""), metadata={k: v for k, v in data.items() if k != "value"})
    vault.set_secret(environment, secret, entry)
    return ClassifyResult(secret=secret, environment=environment, level=level, previous=previous)


def get_classification(vault, environment: str, secret: str) -> ClassifyResult:
    """Get the classification level of a secret."""
    entry = _get_entry_or_raise(vault, environment, secret)
    data = entry.to_dict()
    level = data.get("classification", "internal")
    return ClassifyResult(secret=secret, environment=environment, level=level)


def list_by_classification(vault, environment: str, level: str) -> list[ClassifyResult]:
    """List all secrets in an environment with a given classification level."""
    if level not in CLASSIFICATION_LEVELS:
        raise ClassifyError(
            f"Invalid classification level '{level}'. "
            f"Choose from: {', '.join(CLASSIFICATION_LEVELS)}"
        )
    results = []
    for secret in vault.list_secrets(environment):
        entry = vault.get_secret(environment, secret)
        if entry is None:
            continue
        data = entry.to_dict()
        if data.get("classification", "internal") == level:
            results.append(ClassifyResult(secret=secret, environment=environment, level=level))
    return results
