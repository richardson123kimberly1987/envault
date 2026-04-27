"""rollback.py — Roll back secrets to a previous snapshot or checkpoint.

Provides utilities to revert an entire environment's secrets to a prior
state captured by either the snapshot or checkpoint subsystems.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from envault.snapshot import Snapshot, SnapshotError
from envault.checkpoint import Checkpoint, CheckpointError


class RollbackError(Exception):
    """Raised when a rollback operation cannot be completed."""


@dataclass
class RollbackResult:
    """Outcome of a rollback operation."""

    environment: str
    source_type: str          # "snapshot" or "checkpoint"
    source_id: str            # snapshot timestamp or checkpoint label
    keys_restored: list[str] = field(default_factory=list)
    keys_removed: list[str] = field(default_factory=list)
    rolled_back_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "environment": self.environment,
            "source_type": self.source_type,
            "source_id": self.source_id,
            "keys_restored": self.keys_restored,
            "keys_removed": self.keys_removed,
            "rolled_back_at": self.rolled_back_at,
        }


def rollback_to_snapshot(
    vault: Any,
    environment: str,
    snapshot: Snapshot,
    *,
    dry_run: bool = False,
) -> RollbackResult:
    """Roll back *environment* in *vault* to the state captured in *snapshot*.

    Secrets present in the snapshot are restored (created or overwritten).
    Secrets present in the live environment but absent from the snapshot are
    removed so the environment matches the snapshot exactly.

    Args:
        vault: A :class:`~envault.vault.Vault` instance.
        environment: Target environment name.
        snapshot: The :class:`~envault.snapshot.Snapshot` to restore.
        dry_run: When *True* the vault is not mutated.

    Returns:
        A :class:`RollbackResult` describing what changed.

    Raises:
        RollbackError: If *environment* does not match the snapshot's
            recorded environment.
    """
    if snapshot.environment != environment:
        raise RollbackError(
            f"Snapshot environment '{snapshot.environment}' does not match "
            f"target environment '{environment}'."
        )

    live_keys: set[str] = set(vault.list_secrets(environment))
    snap_keys: set[str] = set(snapshot.secrets.keys())

    keys_restored: list[str] = []
    keys_removed: list[str] = []

    if not dry_run:
        # Restore / overwrite secrets from snapshot
        for key, entry_dict in snapshot.secrets.items():
            vault.set_secret(
                environment,
                key,
                entry_dict.get("value", ""),
            )
            keys_restored.append(key)

        # Remove secrets that did not exist in the snapshot
        for key in live_keys - snap_keys:
            vault.delete_secret(environment, key)
            keys_removed.append(key)

        vault.save()
    else:
        keys_restored = sorted(snap_keys)
        keys_removed = sorted(live_keys - snap_keys)

    return RollbackResult(
        environment=environment,
        source_type="snapshot",
        source_id=snapshot.taken_at,
        keys_restored=sorted(keys_restored),
        keys_removed=sorted(keys_removed),
    )


def rollback_to_checkpoint(
    vault: Any,
    environment: str,
    checkpoint: Checkpoint,
    *,
    dry_run: bool = False,
) -> RollbackResult:
    """Roll back *environment* in *vault* to the state captured in *checkpoint*.

    Behaves identically to :func:`rollback_to_snapshot` but accepts a
    :class:`~envault.checkpoint.Checkpoint` as the source.

    Args:
        vault: A :class:`~envault.vault.Vault` instance.
        environment: Target environment name.
        checkpoint: The :class:`~envault.checkpoint.Checkpoint` to restore.
        dry_run: When *True* the vault is not mutated.

    Returns:
        A :class:`RollbackResult` describing what changed.

    Raises:
        RollbackError: If *environment* does not match the checkpoint's
            recorded environment.
    """
    if checkpoint.environment != environment:
        raise RollbackError(
            f"Checkpoint environment '{checkpoint.environment}' does not match "
            f"target environment '{environment}'."
        )

    live_keys: set[str] = set(vault.list_secrets(environment))
    ckpt_keys: set[str] = set(checkpoint.secrets.keys())

    keys_restored: list[str] = []
    keys_removed: list[str] = []

    if not dry_run:
        for key, entry_dict in checkpoint.secrets.items():
            vault.set_secret(
                environment,
                key,
                entry_dict.get("value", ""),
            )
            keys_restored.append(key)

        for key in live_keys - ckpt_keys:
            vault.delete_secret(environment, key)
            keys_removed.append(key)

        vault.save()
    else:
        keys_restored = sorted(ckpt_keys)
        keys_removed = sorted(live_keys - ckpt_keys)

    return RollbackResult(
        environment=environment,
        source_type="checkpoint",
        source_id=checkpoint.label,
        keys_restored=sorted(keys_restored),
        keys_removed=sorted(keys_removed),
    )
