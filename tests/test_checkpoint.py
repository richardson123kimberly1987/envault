"""Tests for envault.checkpoint."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from envault.checkpoint import (
    Checkpoint,
    CheckpointError,
    list_checkpoints,
    restore_checkpoint,
    save_checkpoint,
)


# ---------------------------------------------------------------------------
# Fake helpers
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str) -> None:
        self.value = value

    def to_dict(self) -> Dict[str, Any]:
        return {"value": self.value}


class _FakeVault:
    def __init__(self, secrets: Optional[Dict[str, Dict[str, str]]] = None) -> None:
        self._secrets: Dict[str, Dict[str, str]] = secrets or {}
        self.saved = False

    def list_secrets(self, env: str) -> List[str]:
        return list(self._secrets.get(env, {}).keys())

    def get_secret(self, env: str, key: str) -> Optional[_FakeEntry]:
        val = self._secrets.get(env, {}).get(key)
        return _FakeEntry(val) if val is not None else None

    def set_secret(self, env: str, key: str, value: str) -> None:
        self._secrets.setdefault(env, {})[key] = value

    def save(self) -> None:
        self.saved = True


# ---------------------------------------------------------------------------
# Checkpoint dataclass
# ---------------------------------------------------------------------------

def test_checkpoint_to_dict_round_trip() -> None:
    cp = Checkpoint(name="v1", environment="prod", secrets={"KEY": {"value": "abc"}}, created_at=1234.0)
    d = cp.to_dict()
    cp2 = Checkpoint.from_dict(d)
    assert cp2.name == "v1"
    assert cp2.environment == "prod"
    assert cp2.secrets == {"KEY": {"value": "abc"}}
    assert cp2.created_at == 1234.0


def test_checkpoint_created_at_defaults_to_now() -> None:
    before = time.time()
    cp = Checkpoint(name="x", environment="dev", secrets={})
    assert cp.created_at >= before


# ---------------------------------------------------------------------------
# save_checkpoint
# ---------------------------------------------------------------------------

def test_save_checkpoint_writes_file(tmp_path: Path) -> None:
    cp_file = str(tmp_path / "cps.json")
    vault = _FakeVault({"staging": {"DB_URL": "postgres://localhost"}})
    cp = save_checkpoint(vault, "staging", "release-1", cp_file)

    assert cp.name == "release-1"
    assert cp.environment == "staging"
    assert "DB_URL" in cp.secrets

    raw = json.loads(Path(cp_file).read_text())
    assert "release-1" in raw["staging"]


def test_save_checkpoint_overwrites_same_name(tmp_path: Path) -> None:
    cp_file = str(tmp_path / "cps.json")
    vault = _FakeVault({"dev": {"X": "1"}})
    save_checkpoint(vault, "dev", "snap", cp_file)
    vault._secrets["dev"]["X"] = "2"
    save_checkpoint(vault, "dev", "snap", cp_file)

    raw = json.loads(Path(cp_file).read_text())
    assert raw["dev"]["snap"]["secrets"]["X"]["value"] == "2"


# ---------------------------------------------------------------------------
# restore_checkpoint
# ---------------------------------------------------------------------------

def test_restore_checkpoint_sets_secrets(tmp_path: Path) -> None:
    cp_file = str(tmp_path / "cps.json")
    vault = _FakeVault({"prod": {"API_KEY": "secret"}})
    save_checkpoint(vault, "prod", "before", cp_file)

    vault2 = _FakeVault()
    restore_checkpoint(vault2, "prod", "before", cp_file)
    assert vault2._secrets["prod"]["API_KEY"] == "secret"


def test_restore_checkpoint_missing_raises(tmp_path: Path) -> None:
    cp_file = str(tmp_path / "cps.json")
    vault = _FakeVault()
    with pytest.raises(CheckpointError, match="not found"):
        restore_checkpoint(vault, "prod", "nonexistent", cp_file)


# ---------------------------------------------------------------------------
# list_checkpoints
# ---------------------------------------------------------------------------

def test_list_checkpoints_returns_all(tmp_path: Path) -> None:
    cp_file = str(tmp_path / "cps.json")
    vault = _FakeVault({"qa": {"TOKEN": "abc"}})
    save_checkpoint(vault, "qa", "cp1", cp_file)
    save_checkpoint(vault, "qa", "cp2", cp_file)

    cps = list_checkpoints("qa", cp_file)
    names = {c.name for c in cps}
    assert names == {"cp1", "cp2"}


def test_list_checkpoints_empty_when_no_file(tmp_path: Path) -> None:
    cp_file = str(tmp_path / "missing.json")
    assert list_checkpoints("prod", cp_file) == []
