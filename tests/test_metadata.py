"""Tests for envault.metadata."""
from __future__ import annotations

import pytest

from envault.metadata import (
    MetadataError,
    MetadataResult,
    get_metadata,
    remove_metadata,
    set_metadata,
)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, data: dict | None = None):
        self._data: dict = data or {}

    def to_dict(self) -> dict:
        return dict(self._data)

    def update_value(self, key: str, value) -> None:
        self._data[key] = value


class _FakeVault:
    def __init__(self, entries: dict | None = None):
        self._entries: dict = entries or {}
        self.saved = False

    def get_secret(self, environment: str, secret: str):
        return self._entries.get((environment, secret))

    def save(self) -> None:
        self.saved = True


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_metadata_result_to_dict():
    r = MetadataResult(environment="prod", secret="API_KEY", metadata={"owner": "alice"})
    d = r.to_dict()
    assert d["environment"] == "prod"
    assert d["secret"] == "API_KEY"
    assert d["metadata"] == {"owner": "alice"}


def test_set_metadata_creates_key():
    entry = _FakeEntry()
    vault = _FakeVault({("prod", "API_KEY"): entry})
    result = set_metadata(vault, "prod", "API_KEY", "owner", "alice")
    assert result.metadata["owner"] == "alice"
    assert vault.saved


def test_set_metadata_updates_existing_key():
    entry = _FakeEntry({"_metadata": {"owner": "alice"}})
    vault = _FakeVault({("prod", "API_KEY"): entry})
    result = set_metadata(vault, "prod", "API_KEY", "owner", "bob")
    assert result.metadata["owner"] == "bob"


def test_set_metadata_missing_secret_raises():
    vault = _FakeVault()
    with pytest.raises(MetadataError, match="not found"):
        set_metadata(vault, "prod", "MISSING", "k", "v")


def test_remove_metadata_deletes_key():
    entry = _FakeEntry({"_metadata": {"owner": "alice", "team": "ops"}})
    vault = _FakeVault({("prod", "API_KEY"): entry})
    result = remove_metadata(vault, "prod", "API_KEY", "team")
    assert "team" not in result.metadata
    assert "owner" in result.metadata
    assert vault.saved


def test_remove_metadata_missing_key_raises():
    entry = _FakeEntry({"_metadata": {}})
    vault = _FakeVault({("prod", "API_KEY"): entry})
    with pytest.raises(MetadataError, match="not found"):
        remove_metadata(vault, "prod", "API_KEY", "nonexistent")


def test_get_metadata_returns_all():
    entry = _FakeEntry({"_metadata": {"a": "1", "b": "2"}})
    vault = _FakeVault({("staging", "DB_PASS"): entry})
    result = get_metadata(vault, "staging", "DB_PASS")
    assert result.metadata == {"a": "1", "b": "2"}


def test_get_metadata_empty_when_none_set():
    entry = _FakeEntry()
    vault = _FakeVault({("dev", "TOKEN"): entry})
    result = get_metadata(vault, "dev", "TOKEN")
    assert result.metadata == {}


def test_get_metadata_missing_secret_raises():
    vault = _FakeVault()
    with pytest.raises(MetadataError):
        get_metadata(vault, "dev", "GHOST")
