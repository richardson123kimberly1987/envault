"""Secret recovery module: attempt to recover a secret from available backups."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


class RecoverError(Exception):
    """Raised when recovery fails."""


@dataclass
class RecoverResult:
    secret_name: str
    environment: str
    recovered_value: Optional[str]
    source: str  # 'snapshot', 'checkpoint', 'history', or 'none'
    success: bool

    def to_dict(self) -> dict:
        return {
            "secret_name": self.secret_name,
            "environment": self.environment,
            "recovered_value": self.recovered_value,
            "source": self.source,
            "success": self.success,
        }


def recover_secret(
    vault,
    environment: str,
    secret_name: str,
    snapshots: Optional[list] = None,
    checkpoints: Optional[list] = None,
    history: Optional[list] = None,
) -> RecoverResult:
    """Attempt to recover a secret value from snapshots, checkpoints, or history.

    Sources are tried in order: snapshots -> checkpoints -> history.
    Returns a RecoverResult indicating which source was used (or 'none').
    """
    # Try snapshots first
    if snapshots:
        for snap in reversed(snapshots):
            secrets = snap.get("secrets", {}).get(environment, {})
            if secret_name in secrets:
                return RecoverResult(
                    secret_name=secret_name,
                    environment=environment,
                    recovered_value=secrets[secret_name],
                    source="snapshot",
                    success=True,
                )

    # Try checkpoints
    if checkpoints:
        for chk in reversed(checkpoints):
            secrets = chk.get("secrets", {}).get(environment, {})
            if secret_name in secrets:
                return RecoverResult(
                    secret_name=secret_name,
                    environment=environment,
                    recovered_value=secrets[secret_name],
                    source="checkpoint",
                    success=True,
                )

    # Try history entries (list of dicts with 'value')
    if history:
        for entry in reversed(history):
            if (
                entry.get("environment") == environment
                and entry.get("secret_name") == secret_name
                and entry.get("value") is not None
            ):
                return RecoverResult(
                    secret_name=secret_name,
                    environment=environment,
                    recovered_value=entry["value"],
                    source="history",
                    success=True,
                )

    return RecoverResult(
        secret_name=secret_name,
        environment=environment,
        recovered_value=None,
        source="none",
        success=False,
    )
