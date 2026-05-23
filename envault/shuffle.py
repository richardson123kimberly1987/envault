"""Shuffle: randomly regenerate a secret value using a configurable character set."""

from __future__ import annotations

import random
import string
from dataclasses import dataclass
from typing import Optional

SHUFFLE_CHARSETS = {
    "alpha": string.ascii_letters,
    "numeric": string.digits,
    "alphanumeric": string.ascii_letters + string.digits,
    "printable": string.ascii_letters + string.digits + string.punctuation,
    "hex": string.hexdigits[:16],
}


class ShuffleError(Exception):
    """Raised when a shuffle operation fails."""


@dataclass
class ShuffleResult:
    key: str
    environment: str
    old_value: str
    new_value: str
    charset: str
    length: int

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "environment": self.environment,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "charset": self.charset,
            "length": self.length,
        }


def shuffle_secret(
    vault,
    environment: str,
    key: str,
    charset: str = "alphanumeric",
    length: int = 32,
    seed: Optional[int] = None,
) -> ShuffleResult:
    """Replace *key* in *environment* with a freshly generated random value."""
    if length < 1:
        raise ShuffleError("length must be at least 1")

    chars = SHUFFLE_CHARSETS.get(charset)
    if chars is None:
        raise ShuffleError(
            f"Unknown charset '{charset}'. "
            f"Valid options: {', '.join(SHUFFLE_CHARSETS)}"
        )

    entry = vault.get_secret(environment, key)
    if entry is None:
        raise ShuffleError(f"Secret '{key}' not found in environment '{environment}'")

    old_value = entry.decrypt()

    rng = random.Random(seed)
    new_value = "".join(rng.choice(chars) for _ in range(length))

    entry.update_value(new_value)
    vault.save()

    return ShuffleResult(
        key=key,
        environment=environment,
        old_value=old_value,
        new_value=new_value,
        charset=charset,
        length=length,
    )
