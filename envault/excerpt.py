"""Excerpt: extract a substring or slice of a secret's decrypted value."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


class ExcerptError(Exception):
    """Raised when an excerpt operation fails."""


@dataclass
class ExcerptResult:
    secret: str
    environment: str
    original_length: int
    excerpt: str
    start: int
    end: int

    def to_dict(self) -> dict:
        return {
            "secret": self.secret,
            "environment": self.environment,
            "original_length": self.original_length,
            "excerpt": self.excerpt,
            "start": self.start,
            "end": self.end,
        }


def _get_entry_or_raise(vault, environment: str, secret: str):
    entry = vault.get_secret(environment, secret)
    if entry is None:
        raise ExcerptError(f"Secret '{secret}' not found in environment '{environment}'")
    return entry


def excerpt_secret(
    vault,
    environment: str,
    secret: str,
    start: int = 0,
    end: Optional[int] = None,
) -> ExcerptResult:
    """Return a slice of the decrypted secret value.

    Parameters
    ----------
    start:
        Start index (inclusive, default 0).
    end:
        End index (exclusive).  ``None`` means the end of the string.
    """
    entry = _get_entry_or_raise(vault, environment, secret)
    value: str = entry.decrypt()

    if start < 0:
        raise ExcerptError("'start' must be a non-negative integer")
    if end is not None and end < start:
        raise ExcerptError("'end' must be greater than or equal to 'start'")

    excerpt = value[start:end]
    actual_end = len(value) if end is None else min(end, len(value))

    return ExcerptResult(
        secret=secret,
        environment=environment,
        original_length=len(value),
        excerpt=excerpt,
        start=start,
        end=actual_end,
    )
