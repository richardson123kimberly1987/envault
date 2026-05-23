"""Tests for envault.retire."""
from __future__ import annotations

import pytest
from envault.retire import (
    RetireResult,
    RetireError,
    retire_secret,
    unretire_secret,
    list_retired,
)


class _FakeEntry:
    def __init__(self, value: str = "s3cr3t", metadata: dict | None = None):
        self._value = value
        self._meta = metadata or {}

    def to_dict(self):
        return {"value": self._value, "metadata": self._meta}

    def update_value(self, value: str, metadata: dict | None = None):
        self._value = value
        if metadata is not None:
            self._meta = metadata


class _FakeVault:
    def __init__(self, secrets: dict | None = None):
        self._secrets: dict[tuple, _FakeEntry] = secrets or {}
        self.saved = False

    def get_secret(self, env: str, name: str):
        return self._secrets.get((env, name))

    def list_secrets(self, env: str):
        return [k[1] for k in self._secrets if k[0] == env]

    def save(self):
        self.saved = True


# --- RetireResult ---

def test_retire_result_to_dict():
    r = RetireResult(secret="KEY", environment="prod", state="retired", retired_at="2024-01-01T00:00:00+00:00")
    d = r.to_dict()
    assert d["secret"] == "KEY"
    assert d["state"] == "retired"
    assert d["retired_at"] == "2024-01-01T00:00:00+00:00"


# --- retire_secret ---

def test_retire_secret_marks_entry():
    entry = _FakeEntry()
    vault = _FakeVault({("prod", "API_KEY"): entry})
    result = retire_secret(vault, "prod", "API_KEY")
    assert result.state == "retired"
    assert result.retired_at is not None
    assert entry._meta.get("retired") is True
    assert vault.saved


def test_retire_secret_missing_raises():
    vault = _FakeVault()
    with pytest.raises(RetireError, match="not found"):
        retire_secret(vault, "prod", "MISSING")


def test_retire_secret_result_has_environment():
    entry = _FakeEntry()
    vault = _FakeVault({("staging", "DB_PASS"): entry})
    result = retire_secret(vault, "staging", "DB_PASS")
    assert result.environment == "staging"
    assert result.secret == "DB_PASS"


# --- unretire_secret ---

def test_unretire_clears_flag():
    entry = _FakeEntry(metadata={"retired": True, "retired_at": "2024-01-01T00:00:00+00:00"})
    vault = _FakeVault({("prod", "API_KEY"): entry})
    result = unretire_secret(vault, "prod", "API_KEY")
    assert result.state == "active"
    assert "retired" not in entry._meta
    assert vault.saved


def test_unretire_preserves_retired_at_in_result():
    ts = "2024-06-01T12:00:00+00:00"
    entry = _FakeEntry(metadata={"retired": True, "retired_at": ts})
    vault = _FakeVault({("prod", "X"): entry})
    result = unretire_secret(vault, "prod", "X")
    assert result.retired_at == ts


def test_unretire_missing_raises():
    vault = _FakeVault()
    with pytest.raises(RetireError):
        unretire_secret(vault, "prod", "GHOST")


# --- list_retired ---

def test_list_retired_returns_only_retired():
    e1 = _FakeEntry(metadata={"retired": True, "retired_at": "2024-01-01T00:00:00+00:00"})
    e2 = _FakeEntry(metadata={})
    vault = _FakeVault({("prod", "OLD_KEY"): e1, ("prod", "NEW_KEY"): e2})
    results = list_retired(vault, "prod")
    assert len(results) == 1
    assert results[0].secret == "OLD_KEY"


def test_list_retired_empty_when_none_retired():
    vault = _FakeVault({("prod", "KEY"): _FakeEntry()})
    results = list_retired(vault, "prod")
    assert results == []


def test_list_retired_empty_environment():
    vault = _FakeVault()
    results = list_retired(vault, "dev")
    assert results == []
