"""Attach and retrieve arbitrary metadata key/value pairs on secrets."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional

METADATA_KEY = "_metadata"


class MetadataError(Exception):
    """Raised when a metadata operation fails."""


@dataclass
class MetadataResult:
    environment: str
    secret: str
    metadata: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "environment": self.environment,
            "secret": self.secret,
            "metadata": self.metadata,
        }


def _get_entry_or_raise(vault, environment: str, secret: str):
    entry = vault.get_secret(environment, secret)
    if entry is None:
        raise MetadataError(
            f"Secret '{secret}' not found in environment '{environment}'."
        )
    return entry


def set_metadata(vault, environment: str, secret: str, key: str, value: str) -> MetadataResult:
    """Set a metadata key on a secret, persisting the change."""
    entry = _get_entry_or_raise(vault, environment, secret)
    raw = entry.to_dict()
    meta: Dict[str, str] = raw.get(METADATA_KEY, {})
    meta[key] = value
    entry.update_value(METADATA_KEY, meta)
    vault.save()
    return MetadataResult(environment=environment, secret=secret, metadata=dict(meta))


def remove_metadata(vault, environment: str, secret: str, key: str) -> MetadataResult:
    """Remove a metadata key from a secret."""
    entry = _get_entry_or_raise(vault, environment, secret)
    raw = entry.to_dict()
    meta: Dict[str, str] = raw.get(METADATA_KEY, {})
    if key not in meta:
        raise MetadataError(
            f"Metadata key '{key}' not found on secret '{secret}'."
        )
    del meta[key]
    entry.update_value(METADATA_KEY, meta)
    vault.save()
    return MetadataResult(environment=environment, secret=secret, metadata=dict(meta))


def get_metadata(vault, environment: str, secret: str) -> MetadataResult:
    """Return all metadata for a secret."""
    entry = _get_entry_or_raise(vault, environment, secret)
    raw = entry.to_dict()
    meta: Dict[str, str] = raw.get(METADATA_KEY, {})
    return MetadataResult(environment=environment, secret=secret, metadata=dict(meta))
