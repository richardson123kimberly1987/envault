"""Tests for envault.history."""
import pytest
from unittest.mock import MagicMock

from envault.history import (
    HistoryEntry,
    HistoryError,
    get_history,
    record_history,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str):
        self._value = value

    def to_dict(self):
        return {"value": self._value}


class _FakeVault:
    def __init__(self):
        self._data: dict = {}
        self._secrets: dict = {}
        self.saved = False

    def get_secret(self, environment, key):
        return self._secrets.get((environment, key))

    def save(self):
        self.saved = True


# ---------------------------------------------------------------------------
# HistoryEntry
# ---------------------------------------------------------------------------

def test_history_entry_to_dict_round_trip():
    entry = HistoryEntry(version=1, encrypted_value="enc", updated_at="2024-01-01T00:00:00+00:00", updated_by="cli")
    assert HistoryEntry.from_dict(entry.to_dict()) == entry


def test_history_entry_fields():
    entry = HistoryEntry(version=3, encrypted_value="abc", updated_at="ts", updated_by="user")
    assert entry.version == 3
    assert entry.encrypted_value == "abc"
    assert entry.updated_by == "user"


# ---------------------------------------------------------------------------
# record_history
# ---------------------------------------------------------------------------

def test_record_history_missing_secret_raises():
    vault = _FakeVault()
    with pytest.raises(HistoryError, match="not found"):
        record_history(vault, "prod", "MISSING_KEY")


def test_record_history_creates_entry():
    vault = _FakeVault()
    vault._secrets[("prod", "DB_PASS")] = _FakeEntry("s3cr3t")
    entry = record_history(vault, "prod", "DB_PASS", updated_by="alice")
    assert entry.version == 1
    assert entry.encrypted_value == "s3cr3t"
    assert entry.updated_by == "alice"
    assert vault.saved


def test_record_history_increments_version():
    vault = _FakeVault()
    vault._secrets[("dev", "API_KEY")] = _FakeEntry("v1")
    record_history(vault, "dev", "API_KEY")
    vault._secrets[("dev", "API_KEY")] = _FakeEntry("v2")
    second = record_history(vault, "dev", "API_KEY")
    assert second.version == 2


def test_record_history_persists_in_data():
    vault = _FakeVault()
    vault._secrets[("staging", "TOKEN")] = _FakeEntry("tok")
    record_history(vault, "staging", "TOKEN")
    assert "_history" in vault._data
    assert "staging" in vault._data["_history"]
    assert len(vault._data["_history"]["staging"]["TOKEN"]) == 1


# ---------------------------------------------------------------------------
# get_history
# ---------------------------------------------------------------------------

def test_get_history_empty():
    vault = _FakeVault()
    assert get_history(vault, "prod", "NOTHING") == []


def test_get_history_returns_newest_first():
    vault = _FakeVault()
    vault._secrets[("prod", "KEY")] = _FakeEntry("a")
    record_history(vault, "prod", "KEY")
    vault._secrets[("prod", "KEY")] = _FakeEntry("b")
    record_history(vault, "prod", "KEY")
    history = get_history(vault, "prod", "KEY")
    assert history[0].version == 2
    assert history[1].version == 1


def test_get_history_limit():
    vault = _FakeVault()
    vault._secrets[("prod", "KEY")] = _FakeEntry("x")
    for _ in range(5):
        record_history(vault, "prod", "KEY")
    history = get_history(vault, "prod", "KEY", limit=3)
    assert len(history) == 3
