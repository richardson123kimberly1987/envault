"""Tests for envault.ttl."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from envault.ttl import (
    TTL_UNITS,
    TTLError,
    TTLResult,
    _parse_ttl,
    check_ttl,
    set_ttl,
)


# ---------------------------------------------------------------------------
# Fake helpers
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str, metadata: dict | None = None):
        self._value = value
        self._metadata = metadata or {}

    def to_dict(self):
        return {"value": self._value, "metadata": self._metadata}


class _FakeVault:
    def __init__(self):
        self._store: dict[tuple, _FakeEntry] = {}

    def get_secret(self, env, name):
        return self._store.get((env, name))

    def set_secret(self, env, name, value, metadata=None):
        self._store[(env, name)] = _FakeEntry(value, metadata or {})


@pytest.fixture()
def vault():
    v = _FakeVault()
    v.set_secret("production", "API_KEY", "s3cr3t")
    return v


# ---------------------------------------------------------------------------
# _parse_ttl
# ---------------------------------------------------------------------------

def test_parse_ttl_seconds():
    assert _parse_ttl(30, "seconds") == 30


def test_parse_ttl_minutes():
    assert _parse_ttl(2, "minutes") == 120


def test_parse_ttl_hours():
    assert _parse_ttl(1, "hours") == 3600


def test_parse_ttl_days():
    assert _parse_ttl(1, "days") == 86400


def test_parse_ttl_unknown_unit_raises():
    with pytest.raises(TTLError, match="Unknown TTL unit"):
        _parse_ttl(5, "weeks")


def test_parse_ttl_non_positive_raises():
    with pytest.raises(TTLError, match="positive integer"):
        _parse_ttl(0, "seconds")


# ---------------------------------------------------------------------------
# set_ttl
# ---------------------------------------------------------------------------

def test_set_ttl_returns_result(vault):
    result = set_ttl(vault, "production", "API_KEY", 60, "seconds")
    assert isinstance(result, TTLResult)
    assert result.ttl_seconds == 60
    assert result.secret == "API_KEY"
    assert result.environment == "production"
    assert not result.already_expired


def test_set_ttl_persists_metadata(vault):
    set_ttl(vault, "production", "API_KEY", 1, "days")
    entry = vault.get_secret("production", "API_KEY")
    meta = entry.to_dict()["metadata"]
    assert meta["ttl_seconds"] == 86400
    assert "ttl_expires_at" in meta


def test_set_ttl_missing_secret_raises(vault):
    with pytest.raises(TTLError, match="not found"):
        set_ttl(vault, "production", "MISSING", 10, "seconds")


# ---------------------------------------------------------------------------
# check_ttl
# ---------------------------------------------------------------------------

def test_check_ttl_no_ttl_returns_none(vault):
    assert check_ttl(vault, "production", "API_KEY") is None


def test_check_ttl_not_expired(vault):
    set_ttl(vault, "production", "API_KEY", 1, "hours")
    result = check_ttl(vault, "production", "API_KEY")
    assert result is not None
    assert not result.already_expired


def test_check_ttl_expired(vault):
    # Manually inject an already-expired TTL
    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    vault.set_secret("production", "API_KEY", "s3cr3t", {"ttl_seconds": 1, "ttl_expires_at": past})
    result = check_ttl(vault, "production", "API_KEY")
    assert result is not None
    assert result.already_expired


def test_check_ttl_missing_secret_raises(vault):
    with pytest.raises(TTLError, match="not found"):
        check_ttl(vault, "production", "NOPE")


def test_ttl_units_constant_not_empty():
    assert len(TTL_UNITS) > 0


def test_ttl_result_to_dict():
    r = TTLResult("KEY", "env", 60, "2025-01-01T00:00:00+00:00", False)
    d = r.to_dict()
    assert d["secret"] == "KEY"
    assert d["ttl_seconds"] == 60
    assert d["already_expired"] is False
