"""Revert a secret to a previous history entry."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from envault.history import HistoryEntry, record_history


class RevertError(Exception):
    """Raised when a revert operation fails."""


@dataclass
class RevertResult:
    secret: str
    environment: str
    reverted_to: str  # ISO timestamp of the history entry used
    previous_value: str
    new_value: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "secret": self.secret,
            "environment": self.environment,
            "reverted_to": self.reverted_to,
            "previous_value": self.previous_value,
            "new_value": self.new_value,
        }


def revert_secret(
    vault: Any,
    environment: str,
    secret: str,
    index: int = -1,
) -> RevertResult:
    """Revert *secret* in *environment* to a previous history entry.

    Parameters
    ----------
    vault:
        An open :class:`~envault.vault.Vault` instance.
    environment:
        Target environment name.
    secret:
        Secret key to revert.
    index:
        Index into the history list (default ``-1`` means the most recent
        entry *before* the current value, i.e. ``history[-1]``).
    """
    entry = vault.get_secret(environment, secret)
    if entry is None:
        raise RevertError(f"Secret '{secret}' not found in environment '{environment}'.")

    data = entry.to_dict()
    history: list[dict[str, Any]] = data.get("history", [])

    if not history:
        raise RevertError(
            f"No history available for secret '{secret}' in environment '{environment}'."
        )

    try:
        target: dict[str, Any] = history[index]
    except IndexError:
        raise RevertError(
            f"History index {index} is out of range (history has {len(history)} entries)."
        )

    old_value: str = data.get("value", "")
    new_value: str = target["value"]

    vault.set_secret(environment, secret, new_value)
    record_history(vault, environment, secret, action="revert")
    vault.save()

    return RevertResult(
        secret=secret,
        environment=environment,
        reverted_to=target.get("timestamp", ""),
        previous_value=old_value,
        new_value=new_value,
    )
