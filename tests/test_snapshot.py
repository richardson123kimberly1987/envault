"""Tests for envault.snapshot."""
from __future__ import annotations

import json
import os
import pytest

from envault.snapshot import (
    Snapshot,
    SnapshotError,
    load_snapshot,
    restore_snapshot,
    save_snapshot,
    take_snapshot,
)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str) -> None:
        self.value = value

    def to_dict(self):
        return {"value": self.value, "metadata": {}}


class _FakeVault:
    def __init__(self, secrets: dict):
        self._secrets = secrets  # {env: {key: _FakeEntry}}
        self.saved = False
        self.set_calls: list = []

    def list_secrets(self, env):
        return list(self._secrets.get(env, {}).keys()) or (None if env not in self._secrets else [])

    def get_secret(self, env, key):
        return self._secrets.get(env, {}).get(key)

    def set_secret(self, env, key, value, passphrase):
        self._secrets.setdefault(env, {})[key] = _FakeEntry(value)
        self.set_calls.append((env, key, value))

    def save(self, passphrase):
        self.saved = True


# ---------------------------------------------------------------------------
# Snapshot model
# ---------------------------------------------------------------------------

def test_snapshot_to_dict_roundtrip():
    snap = Snapshot(environment="prod", data={"KEY": {"value": "v"}}, created_at="2024-01-01T00:00:00")
    d = snap.to_dict()
    restored = Snapshot.from_dict(d)
    assert restored.environment == "prod"
    assert restored.data == {"KEY": {"value": "v"}}
    assert restored.created_at == "2024-01-01T00:00:00"


def test_snapshot_created_at_auto_set():
    snap = Snapshot(environment="dev", data={})
    assert snap.created_at is not None and len(snap.created_at) > 0


# ---------------------------------------------------------------------------
# take_snapshot
# ---------------------------------------------------------------------------

def test_take_snapshot_captures_secrets():
    vault = _FakeVault({"prod": {"DB_URL": _FakeEntry("postgres://"), "API_KEY": _FakeEntry("abc")}})
    snap = take_snapshot(vault, "prod")
    assert snap.environment == "prod"
    assert "DB_URL" in snap.data
    assert "API_KEY" in snap.data


def test_take_snapshot_missing_environment_raises():
    vault = _FakeVault({})
    with pytest.raises(SnapshotError, match="not found"):
        take_snapshot(vault, "staging")


# ---------------------------------------------------------------------------
# save / load
# ---------------------------------------------------------------------------

def test_save_and_load_snapshot(tmp_path):
    path = str(tmp_path / "snap.json")
    snap = Snapshot(environment="dev", data={"FOO": {"value": "bar"}}, created_at="2024-06-01T12:00:00")
    save_snapshot(snap, path)
    assert os.path.exists(path)
    loaded = load_snapshot(path)
    assert loaded.environment == "dev"
    assert loaded.data["FOO"]["value"] == "bar"


def test_load_snapshot_missing_file_raises(tmp_path):
    with pytest.raises(SnapshotError, match="Failed to read"):
        load_snapshot(str(tmp_path / "nonexistent.json"))


def test_load_snapshot_invalid_json_raises(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("not-json")
    with pytest.raises(SnapshotError, match="Failed to read"):
        load_snapshot(str(bad))


# ---------------------------------------------------------------------------
# restore_snapshot
# ---------------------------------------------------------------------------

def test_restore_snapshot_sets_all_secrets():
    vault = _FakeVault({"prod": {}})
    snap = Snapshot(environment="prod", data={"X": {"value": "1"}, "Y": {"value": "2"}})
    count = restore_snapshot(vault, snap, passphrase="pw")
    assert count == 2
    assert vault.saved is True
    keys_set = [call[1] for call in vault.set_calls]
    assert "X" in keys_set and "Y" in keys_set


def test_restore_snapshot_empty_data():
    vault = _FakeVault({"dev": {}})
    snap = Snapshot(environment="dev", data={})
    count = restore_snapshot(vault, snap, passph count == 0
    assert vault.saved is True
