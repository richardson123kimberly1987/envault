"""Chain multiple secrets together so that one secret's value is derived
from a sequence of transformations applied to a source secret."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


CHAIN_STEPS = ["upper", "lower", "strip", "reverse", "base64_encode", "base64_decode"]


class ChainError(Exception):
    """Raised when a chain operation fails."""


@dataclass
class ChainResult:
    secret: str
    env: str
    steps: List[str]
    original: str
    result: str

    def to_dict(self) -> dict:
        return {
            "secret": self.secret,
            "env": self.env,
            "steps": self.steps,
            "original": self.original,
            "result": self.result,
        }


def _apply_step(value: str, step: str) -> str:
    import base64

    if step == "upper":
        return value.upper()
    if step == "lower":
        return value.lower()
    if step == "strip":
        return value.strip()
    if step == "reverse":
        return value[::-1]
    if step == "base64_encode":
        return base64.b64encode(value.encode()).decode()
    if step == "base64_decode":
        try:
            return base64.b64decode(value.encode()).decode()
        except Exception as exc:  # pragma: no cover
            raise ChainError(f"base64_decode failed: {exc}") from exc
    raise ChainError(f"Unknown chain step: '{step}'. Valid steps: {CHAIN_STEPS}")


def chain_secret(
    vault,
    env: str,
    secret: str,
    steps: List[str],
    passphrase: str,
    *,
    save: bool = True,
) -> ChainResult:
    """Apply *steps* sequentially to the plaintext of *secret* and persist
    the result back into the vault (unless *save* is False)."""
    entry = vault.get_secret(env, secret)
    if entry is None:
        raise ChainError(f"Secret '{secret}' not found in environment '{env}'")

    for step in steps:
        if step not in CHAIN_STEPS:
            raise ChainError(f"Unknown chain step: '{step}'. Valid steps: {CHAIN_STEPS}")

    from envault.crypto import decrypt

    original = decrypt(entry.to_dict()["value"], passphrase)
    value = original
    for step in steps:
        value = _apply_step(value, step)

    if save:
        vault.set_secret(env, secret, value, passphrase)
        vault.save()

    return ChainResult(
        secret=secret,
        env=env,
        steps=steps,
        original=original,
        result=value,
    )
