"""Tests for envault.revert."""
from __future__ import annotations

import pytest

from envault.revert import RevertError, RevertResult, revert_secret


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str, history: list[dict] | None = None):
        self._value = value
        self._history = history or []

    def to_dict(self):
        return {"value": self._value, "history": self._history}


class _FakeVault:
    def __init__(self):
        self._store: dict[tuple[str, str], _FakeEntry] = {}
        self._saved = False
        self._history_calls: list[tuple] = []

    def get_secret(self, env: str, key: str):
        return self._store.get((env, key))

    def set_secret(self, env: str, key: str, value: str):
        existing = self._store.get((env, key))
        history = existing.to_dict().get("history", []) if existing else []
        self._store[(env, key)] = _FakeEntry(value, history)

    def save(self):
        self._saved = True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_vault_with_history(env, key, current, history_values):
    vault = _FakeVault()
    history = [{"value": v, "timestamp": f"2024-01-0{i+1}T00:00:00"}
               for i, v in enumerate(history_values)]
    vault._store[(env, key)] = _FakeEntry(current, history)
    return vault


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_revert_result_to_dict():
    r = RevertResult(
        secret="DB_PASS",
        environment="prod",
        reverted_to="2024-01-01T00:00:00",
        previous_value="new",
        new_value="old",
    )
    d = r.to_dict()
    assert d["secret"] == "DB_PASS"
    assert d["environment"] == "prod"
    assert d["reverted_to"] == "2024-01-01T00:00:00"
    assert d["previous_value"] == "new"
    assert d["new_value"] == "old"


def test_revert_missing_secret_raises():
    vault = _FakeVault()
    with pytest.raises(RevertError, match="not found"):
        revert_secret(vault, "prod", "MISSING")


def test_revert_no_history_raises():
    vault = _FakeVault()
    vault._store[("prod", "KEY")] = _FakeEntry("value", [])
    with pytest.raises(RevertError, match="No history"):
        revert_secret(vault, "prod", "KEY")


def test_revert_index_out_of_range_raises():
    vault = _make_vault_with_history("prod", "KEY", "v3", ["v1", "v2"])
    with pytest.raises(RevertError, match="out of range"):
        revert_secret(vault, "prod", "KEY", index=10)


def test_revert_default_index_uses_last_history_entry():
    vault = _make_vault_with_history("prod", "KEY", "v3", ["v1", "v2"])
    # Patch record_history to a no-op so we don't need a real vault
    import envault.revert as mod
    original = mod.record_history
    mod.record_history = lambda *a, **kw: None
    try:
        result = revert_secret(vault, "prod", "KEY", index=-1)
    finally:
        mod.record_history = original

    assert result.new_value == "v2"
    assert result.previous_value == "v3"
    assert vault._saved is True


def test_revert_specific_index():
    vault = _make_vault_with_history("staging", "API_KEY", "current", ["first", "second", "third"])
    import envault.revert as mod
    original = mod.record_history
    mod.record_history = lambda *a, **kw: None
    try:
        result = revert_secret(vault, "staging", "API_KEY", index=0)
    finally:
        mod.record_history = original

    assert result.new_value == "first"
    assert result.environment == "staging"
    assert result.secret == "API_KEY"
