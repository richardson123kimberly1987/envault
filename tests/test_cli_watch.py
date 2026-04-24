"""Tests for envault.cli_watch."""
from __future__ import annotations

from unittest.mock import patch

import pytest
from click.testing import CliRunner

from envault.cli_watch import watch_group
from envault.watch import WatchEvent


@pytest.fixture()
def runner():
    return CliRunner()


def _invoke(runner, args, catch_exceptions=False):
    return runner.invoke(watch_group, args, catch_exceptions=catch_exceptions)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value):
        self._value = value

    def to_dict(self):
        return {"value": self._value}


class _FakeVault:
    def __init__(self):
        self._data = {"prod": {"KEY": "val"}}

    def list_environments(self):
        return list(self._data.keys())

    def list_secrets(self, env):
        return list(self._data.get(env, {}).keys())

    def get_secret(self, env, key):
        v = self._data.get(env, {}).get(key)
        return _FakeEntry(v) if v is not None else None


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_start_unknown_environment_exits(runner):
    fake_vault = _FakeVault()
    with patch("envault.cli_watch._get_vault", return_value=fake_vault), \
         patch("envault.watch.time.sleep", side_effect=KeyboardInterrupt):
        result = _invoke(
            runner,
            ["start", "ghost", "--vault-file", "v.json", "--passphrase", "pw"],
        )
    assert result.exit_code != 0
    assert "not found" in result.output.lower() or "watch error" in result.output.lower()


def test_start_text_output(runner):
    fake_vault = _FakeVault()
    event = WatchEvent("prod", "KEY", "modified", "old", "new")

    def _fake_watch(vault, env, cb, interval, max_iterations=None):
        cb(event)
        raise KeyboardInterrupt

    with patch("envault.cli_watch._get_vault", return_value=fake_vault), \
         patch("envault.cli_watch.watch_environment", side_effect=_fake_watch):
        result = _invoke(
            runner,
            ["start", "prod", "--vault-file", "v.json", "--passphrase", "pw", "--format", "text"],
        )

    assert "MODIFIED" in result.output
    assert "KEY" in result.output


def test_start_json_output(runner):
    import json as _json

    fake_vault = _FakeVault()
    event = WatchEvent("prod", "KEY", "added", None, "new")

    def _fake_watch(vault, env, cb, interval, max_iterations=None):
        cb(event)
        raise KeyboardInterrupt

    with patch("envault.cli_watch._get_vault", return_value=fake_vault), \
         patch("envault.cli_watch.watch_environment", side_effect=_fake_watch):
        result = _invoke(
            runner,
            ["start", "prod", "--vault-file", "v.json", "--passphrase", "pw", "--format", "json"],
        )

    lines = [l for l in result.output.splitlines() if l.strip().startswith("{")]
    assert lines, "Expected JSON line in output"
    data = _json.loads(lines[0])
    assert data["event_type"] == "added"
    assert data["key"] == "KEY"


def test_vault_load_error_exits(runner):
    with patch("envault.cli_watch._get_vault", side_effect=RuntimeError("bad vault")):
        result = _invoke(
            runner,
            ["start", "prod", "--vault-file", "v.json", "--passphrase", "pw"],
        )
    assert result.exit_code != 0
    assert "bad vault" in result.output
