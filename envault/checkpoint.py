"""Checkpoint feature: save and restore named vault states."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

CHECKPOINT_FILE = ".envault_checkpoints.json"


class CheckpointError(Exception):
    """Raised when a checkpoint operation fails."""


@dataclass
class Checkpoint:
    name: str
    environment: str
    secrets: Dict[str, Any]
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "environment": self.environment,
            "secrets": self.secrets,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Checkpoint":
        return cls(
            name=data["name"],
            environment=data["environment"],
            secrets=data["secrets"],
            created_at=data.get("created_at", 0.0),
        )


def _load_checkpoints(path: str) -> Dict[str, Any]:
    p = Path(path)
    if not p.exists():
        return {}
    return json.loads(p.read_text())


def _save_checkpoints(path: str, data: Dict[str, Any]) -> None:
    Path(path).write_text(json.dumps(data, indent=2))


def save_checkpoint(
    vault: Any,
    environment: str,
    name: str,
    checkpoint_path: str = CHECKPOINT_FILE,
) -> Checkpoint:
    """Capture the current state of an environment as a named checkpoint."""
    secrets = {}
    for key in vault.list_secrets(environment):
        entry = vault.get_secret(environment, key)
        if entry is not None:
            secrets[key] = entry.to_dict()

    cp = Checkpoint(name=name, environment=environment, secrets=secrets)
    data = _load_checkpoints(checkpoint_path)
    env_cps = data.setdefault(environment, {})
    env_cps[name] = cp.to_dict()
    _save_checkpoints(checkpoint_path, data)
    return cp


def restore_checkpoint(
    vault: Any,
    environment: str,
    name: str,
    checkpoint_path: str = CHECKPOINT_FILE,
) -> Checkpoint:
    """Restore an environment to a previously saved checkpoint."""
    data = _load_checkpoints(checkpoint_path)
    env_cps = data.get(environment, {})
    if name not in env_cps:
        raise CheckpointError(f"Checkpoint '{name}' not found for environment '{environment}'.")

    cp = Checkpoint.from_dict(env_cps[name])
    for key, entry_dict in cp.secrets.items():
        vault.set_secret(environment, key, entry_dict.get("value", ""))
    return cp


def list_checkpoints(
    environment: str,
    checkpoint_path: str = CHECKPOINT_FILE,
) -> List[Checkpoint]:
    """Return all checkpoints saved for the given environment."""
    data = _load_checkpoints(checkpoint_path)
    env_cps = data.get(environment, {})
    return [Checkpoint.from_dict(v) for v in env_cps.values()]
