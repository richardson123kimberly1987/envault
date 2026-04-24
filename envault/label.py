"""Label management for secrets — attach arbitrary key/value metadata labels."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


LABEL_KEY_MAX_LEN = 64
LABEL_VALUE_MAX_LEN = 256


class LabelError(Exception):
    """Raised when a label operation fails."""


@dataclass
class LabelResult:
    secret: str
    environment: str
    labels: Dict[str, str] = field(default_factory=dict)
    changed: bool = False

    def to_dict(self) -> dict:
        return {
            "secret": self.secret,
            "environment": self.environment,
            "labels": self.labels,
            "changed": self.changed,
        }


def _validate_label(key: str, value: str) -> None:
    if not key or len(key) > LABEL_KEY_MAX_LEN:
        raise LabelError(
            f"Label key must be 1–{LABEL_KEY_MAX_LEN} characters, got {len(key)!r}"
        )
    if len(value) > LABEL_VALUE_MAX_LEN:
        raise LabelError(
            f"Label value must be ≤{LABEL_VALUE_MAX_LEN} characters, got {len(value)!r}"
        )


def set_label(vault, environment: str, secret: str, key: str, value: str) -> LabelResult:
    """Add or update a label on a secret entry."""
    _validate_label(key, value)
    entry = vault.get_secret(environment, secret)
    if entry is None:
        raise LabelError(f"Secret {secret!r} not found in environment {environment!r}")
    data = entry.to_dict()
    labels: Dict[str, str] = data.get("labels") or {}
    changed = labels.get(key) != value
    labels[key] = value
    data["labels"] = labels
    vault.set_secret(environment, secret, data)
    return LabelResult(secret=secret, environment=environment, labels=labels, changed=changed)


def remove_label(vault, environment: str, secret: str, key: str) -> LabelResult:
    """Remove a label from a secret entry."""
    entry = vault.get_secret(environment, secret)
    if entry is None:
        raise LabelError(f"Secret {secret!r} not found in environment {environment!r}")
    data = entry.to_dict()
    labels: Dict[str, str] = data.get("labels") or {}
    if key not in labels:
        raise LabelError(f"Label {key!r} not found on secret {secret!r}")
    del labels[key]
    data["labels"] = labels
    vault.set_secret(environment, secret, data)
    return LabelResult(secret=secret, environment=environment, labels=labels, changed=True)


def list_labels(vault, environment: str, secret: str) -> LabelResult:
    """Return all labels attached to a secret entry."""
    entry = vault.get_secret(environment, secret)
    if entry is None:
        raise LabelError(f"Secret {secret!r} not found in environment {environment!r}")
    data = entry.to_dict()
    labels: Dict[str, str] = data.get("labels") or {}
    return LabelResult(secret=secret, environment=environment, labels=labels, changed=False)
