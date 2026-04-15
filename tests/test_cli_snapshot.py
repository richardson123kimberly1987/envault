"""Tests for envault.cli_snapshot CLI commands."""
from __future__ import annotations

import json
import os
import pytest
from click.testing import CliRunner

from envault.cli_snapshot import snapshot_group
from envault.snapshot import Snapshot, save_snapshot


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def runner():
    return CliRunner()


class _FakeEntry:
    def __init__(self, value):
        self.value = value

    def to_dict(self):
        return {"value": self.value}


class _FakeVault:
    def __init__(self):
        self._secrets = {"prod": {"DB": _FakeEntry("postgres://"), "TOKEN": _FakeEntry("tok")}}
        self.saved = False
        self.set_calls = []

    def list_secrets(self, env):
        return list(self._secrets.get(env, {}).keys()) if env in self._secrets else None

    def get_secret(self, env, key):
        return self._secrets.get(env, {}).get(key)

    def set_secret(self, env, key, value, passphrase):
        self._secrets.setdefault(env, {})[key] = _FakeEntry(value)
        self.set_calls.append((env, key, value))

    def save(self, passphrase):
        self.saved = True


def _invoke(runner, args, vault, catch_exceptions=False):
    """Invoke snapshot_group with a pre-built vault injected via obj."""
    return runner.invoke(snapshot_group, args, obj={"vault": vault}, catch_exceptions=catch_exceptions)


# ---------------------------------------------------------------------------
# list command
# ---------------------------------------------------------------------------

def test_list_shows_keys(runner, tmp_path):
    snap = Snapshot(environment="prod", data={"A": {"value": "1"}, "B": {"value": "2"}},
                    created_at="2024-01-01T00:00:00")
    snap_file = str(tmp_path / "snap.json")
    save_snapshot(snap, snap_file)

    result = runner.invoke(snapshot_group, ["list", snap_file])
    assert result.exit_code == 0
    assert "prod" in result.output
    assert "A" in result.output
    assert "B" in result.output


def test_list_missing_file_fails(runner, tmp_path):
    result = runner.invoke(snapshot_group, ["list", str(tmp_path / "nope.json")])
    assert result.exit_code != 0
    assert "Error" in result.output


# ---------------------------------------------------------------------------
# take command (monkeypatched vault)
# ---------------------------------------------------------------------------

def test_take_writes_json(runner, tmp_path, monkeypatch):
    vault = _FakeVault()
    monkeypatch.setattr("envault.cli_snapshot._get_vault", lambda ctx, pw: vault)
    out = str(tmp_path / "out.json")
    result = runner.invoke(
        snapshot_group,
        ["take", "prod", out, "--passphrase", "pw"],
        obj={},
    )
    assert result.exit_code == 0, result.output
    assert os.path.exists(out)
    with open(out) as fh:
        data = json.load(fh)
    assert data["environment"] == "prod"
    assert "DB" in data["data"]


# ---------------------------------------------------------------------------
# restore command (monkeypatched vault)
# ---------------------------------------------------------------------------

def test_restore_from_snapshot(runner, tmp_path, monkeypatch):
    vault = _FakeVault()
    monkeypatch.setattr("envault.cli_snapshot._get_vault", lambda ctx, pw: vault)
    snap = Snapshot(environment="prod", data={"NEW_KEY": {"value": "newval"}})
    snap_file = str(tmp_path / "snap.json")
    save_snapshot(snap, snap_file)

    result = runner.invoke(
        snapshot_group,
        ["restore", snap_file, "--passphrase", "pw", "--yes"],
        obj={},
    )
    assert result.exit_code == 0, result.output
    assert "Restored 1" in result.output
    assert vault.saved is True


def test_restore_invalid_file_fails(runner, tmp_path, monkeypatch):
    vault = _FakeVault()
    monkeypatch.setattr("envault.cli_snapshot._get_vault", lambda ctx, pw: vault)
    result = runner.invoke(
        snapshot_group,
        ["restore", str(tmp_path / "missing.json"), "--passphrase", "pw", "--yes"],
        obj={},
    )
    assert result.exit_code != 0
    assert "Error" in result.output
