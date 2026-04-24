"""Tests for envault.watch."""
from __future__ import annotations

import pytest

from envault.watch import (
    WATCH_EVENTS,
    WatchError,
    WatchEvent,
    diff_snapshots,
    watch_environment,
)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str):
        self._value = value

    def to_dict(self):
        return {"value": self._value}


class _FakeVault:
    def __init__(self, envs: dict):
        # envs: {env_name: {key: value}}
        self._envs = envs

    def list_environments(self):
        return list(self._envs.keys())

    def list_secrets(self, environment):
        return list(self._envs.get(environment, {}).keys())

    def get_secret(self, environment, key):
        val = self._envs.get(environment, {}).get(key)
        return _FakeEntry(val) if val is not None else None


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------

def test_watch_events_constant_not_empty():
    assert len(WATCH_EVENTS) > 0


def test_watch_event_to_dict():
    e = WatchEvent("prod", "DB_URL", "added", None, "postgres://")
    d = e.to_dict()
    assert d["environment"] == "prod"
    assert d["key"] == "DB_URL"
    assert d["event_type"] == "added"
    assert d["old_value"] is None
    assert d["new_value"] == "postgres://"


def test_diff_snapshots_added():
    events = diff_snapshots("dev", {}, {"NEW_KEY": "val"})
    assert len(events) == 1
    assert events[0].event_type == "added"
    assert events[0].key == "NEW_KEY"


def test_diff_snapshots_removed():
    events = diff_snapshots("dev", {"OLD_KEY": "val"}, {})
    assert len(events) == 1
    assert events[0].event_type == "removed"


def test_diff_snapshots_modified():
    events = diff_snapshots("dev", {"K": "old"}, {"K": "new"})
    assert len(events) == 1
    assert events[0].event_type == "modified"
    assert events[0].old_value == "old"
    assert events[0].new_value == "new"


def test_diff_snapshots_no_change():
    events = diff_snapshots("dev", {"K": "same"}, {"K": "same"})
    assert events == []


def test_watch_environment_unknown_env_raises():
    vault = _FakeVault({})
    with pytest.raises(WatchError, match="not found"):
        watch_environment(vault, "ghost", lambda e: None, interval=0, max_iterations=0)


def test_watch_environment_detects_change(monkeypatch):
    """Simulate a value change between poll iterations."""
    state = {"prod": {"API_KEY": "secret1"}}
    vault = _FakeVault(state)

    call_count = [0]

    def _fake_sleep(_):
        # Mutate vault state on first sleep to simulate a change
        if call_count[0] == 0:
            state["prod"]["API_KEY"] = "secret2"
        call_count[0] += 1

    monkeypatch.setattr("envault.watch.time.sleep", _fake_sleep)

    collected = []
    watch_environment(vault, "prod", collected.append, interval=0, max_iterations=1)

    assert len(collected) == 1
    assert collected[0].event_type == "modified"
    assert collected[0].old_value == "secret1"
    assert collected[0].new_value == "secret2"


def test_watch_environment_no_change_no_callback(monkeypatch):
    monkeypatch.setattr("envault.watch.time.sleep", lambda _: None)
    vault = _FakeVault({"staging": {"PORT": "8080"}})
    collected = []
    watch_environment(vault, "staging", collected.append, interval=0, max_iterations=1)
    assert collected == []
