"""Trim whitespace and normalize secret values."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

TRIM_MODES = ("full", "leading", "trailing", "lines")


class TrimError(Exception):
    """Raised when trimming fails."""


@dataclass
class TrimResult:
    secret: str
    environment: str
    original: str
    trimmed: str
    changed: bool
    mode: str

    def to_dict(self) -> dict:
        return {
            "secret": self.secret,
            "environment": self.environment,
            "original": self.original,
            "trimmed": self.trimmed,
            "changed": self.changed,
            "mode": self.mode,
        }


def _apply_trim(value: str, mode: str) -> str:
    if mode == "full":
        return value.strip()
    elif mode == "leading":
        return value.lstrip()
    elif mode == "trailing":
        return value.rstrip()
    elif mode == "lines":
        return "\n".join(line.strip() for line in value.splitlines())
    raise TrimError(f"Unknown trim mode '{mode}'. Choose from: {', '.join(TRIM_MODES)}")


def trim_secret(
    vault,
    secret: str,
    environment: str,
    passphrase: str,
    mode: str = "full",
    dry_run: bool = False,
) -> TrimResult:
    """Trim whitespace from a secret value."""
    if mode not in TRIM_MODES:
        raise TrimError(f"Unknown trim mode '{mode}'. Choose from: {', '.join(TRIM_MODES)}")

    entry = vault.get_secret(secret, environment)
    if entry is None:
        raise TrimError(f"Secret '{secret}' not found in environment '{environment}'.")

    original = entry.decrypt(passphrase)
    trimmed = _apply_trim(original, mode)
    changed = trimmed != original

    if changed and not dry_run:
        entry.update_value(trimmed, passphrase)
        vault.save()

    return TrimResult(
        secret=secret,
        environment=environment,
        original=original,
        trimmed=trimmed,
        changed=changed,
        mode=mode,
    )


def trim_all(
    vault,
    environment: str,
    passphrase: str,
    mode: str = "full",
    dry_run: bool = False,
) -> list[TrimResult]:
    """Trim all secrets in an environment."""
    results = []
    for secret in vault.list_secrets(environment):
        try:
            result = trim_secret(vault, secret, environment, passphrase, mode=mode, dry_run=dry_run)
            results.append(result)
        except TrimError:
            pass
    return results
