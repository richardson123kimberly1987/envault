"""splice.py – insert or replace a substring segment within a secret value."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class SpliceError(Exception):
    """Raised when a splice operation fails."""


@dataclass
class SpliceResult:
    secret: str
    environment: str
    original: str
    spliced: str
    start: int
    end: int
    replacement: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "secret": self.secret,
            "environment": self.environment,
            "original": self.original,
            "spliced": self.spliced,
            "start": self.start,
            "end": self.end,
            "replacement": self.replacement,
        }


def _get_entry_or_raise(vault: Any, environment: str, secret: str) -> Any:
    entry = vault.get_secret(environment, secret)
    if entry is None:
        raise SpliceError(f"Secret '{secret}' not found in environment '{environment}'")
    return entry


def splice_secret(
    vault: Any,
    environment: str,
    secret: str,
    start: int,
    end: int,
    replacement: str,
    passphrase: str,
) -> SpliceResult:
    """Replace characters [start:end] in the decrypted value with *replacement*."""
    entry = _get_entry_or_raise(vault, environment, secret)
    original = entry.decrypt(passphrase)

    length = len(original)
    if start < 0 or end < start or end > length:
        raise SpliceError(
            f"Invalid splice range [{start}:{end}] for value of length {length}"
        )

    spliced = original[:start] + replacement + original[end:]
    entry.update_value(spliced, passphrase)
    vault.set_secret(environment, secret, entry)

    return SpliceResult(
        secret=secret,
        environment=environment,
        original=original,
        spliced=spliced,
        start=start,
        end=end,
        replacement=replacement,
    )
