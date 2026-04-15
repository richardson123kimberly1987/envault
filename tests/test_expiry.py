"""Tests for envault.expiry."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

import pytest

from envault.expiry import (
    EXPIRY_DATE_FORMAT,
    ExpiryError,
    ExpiryResult,
    check_expiry,
    list_expiring,
    set_expiry,
)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, key: str, value: str, expires_at: Optional[str] = None):
        self._key = key
        self._value = value
        self._expires_at = expires_at

    def to_dict(self):
        d = {"key": self._key, "value": self._value}
        if self._expires_at:
            d["expires_at"] = self._expires_at
        return d


class _FakeVault:
    def __init__(self):
        self._store: Dict[str, Dict[str, _FakeEntry]] = {}

    def get_secret(self, env: str, key: str) -> Optional[_FakeEntry]:
        return self._store.get(env, {}).get(key)

    def set_secret(self, env: str, key: str, value: str, metadata: Optional[dict] = None):
        expires_at = (metadata or {}).get("expires_at")
        self._store.setdefault(env, {})[key] = _FakeEntry(key, value, expires_at)

    def list_secrets(self, env: str) -> List[str]:
        return list(self._store.get(env, {}).keys())


@pytest.fixture
def vault():
    v = _FakeVault()
    v.set_secret("prod", "DB_PASS", "s3cr3t")
    return v


# ---------------------------------------------------------------------------
# ExpiryResult.to_dict
# ---------------------------------------------------------------------------

def test_expiry_result_to_dict():
    r = ExpiryResult("prod", "KEY", "2030-01-01T00:00:00Z", False, 100)
    d = r.to_dict()
    assert d["environment"] == "prod"
    assert d["key"] == "KEY"
    assert d["is_expired"] is False
    assert d["days_remaining"] == 100


# ---------------------------------------------------------------------------
# set_expiry
# ---------------------------------------------------------------------------

def test_set_expiry_returns_result(vault):
    future = (datetime.now(timezone.utc) + timedelta(days=10)).strftime(EXPIRY_DATE_FORMAT)
    result = set_expiry(vault, "prod", "DB_PASS", future)
    assert isinstance(result, ExpiryResult)
    assert result.expires_at == future
    assert result.is_expired is False


def test_set_expiry_missing_secret_raises(vault):
    future = (datetime.now(timezone.utc) + timedelta(days=5)).strftime(EXPIRY_DATE_FORMAT)
    with pytest.raises(ExpiryError, match="not found"):
        set_expiry(vault, "prod", "MISSING", future)


def test_set_expiry_invalid_format_raises(vault):
    with pytest.raises(ExpiryError, match="Invalid expiry date format"):
        set_expiry(vault, "prod", "DB_PASS", "not-a-date")


# ---------------------------------------------------------------------------
# check_expiry
# ---------------------------------------------------------------------------

def test_check_expiry_no_expiry(vault):
    result = check_expiry(vault, "prod", "DB_PASS")
    assert result.expires_at is None
    assert result.is_expired is False
    assert result.days_remaining is None


def test_check_expiry_future(vault):
    future = (datetime.now(timezone.utc) + timedelta(days=15)).strftime(EXPIRY_DATE_FORMAT)
    vault.set_secret("prod", "API_KEY", "abc", metadata={"expires_at": future})
    result = check_expiry(vault, "prod", "API_KEY")
    assert result.is_expired is False
    assert result.days_remaining is not None and result.days_remaining >= 14


def test_check_expiry_past(vault):
    past = (datetime.now(timezone.utc) - timedelta(days=1)).strftime(EXPIRY_DATE_FORMAT)
    vault.set_secret("prod", "OLD_KEY", "xyz", metadata={"expires_at": past})
    result = check_expiry(vault, "prod", "OLD_KEY")
    assert result.is_expired is True
    assert result.days_remaining is None


def test_check_expiry_missing_secret_raises(vault):
    with pytest.raises(ExpiryError):
        check_expiry(vault, "prod", "GHOST")


# ---------------------------------------------------------------------------
# list_expiring
# ---------------------------------------------------------------------------

def test_list_expiring_returns_only_soon(vault):
    soon = (datetime.now(timezone.utc) + timedelta(days=5)).strftime(EXPIRY_DATE_FORMAT)
    far = (datetime.now(timezone.utc) + timedelta(days=60)).strftime(EXPIRY_DATE_FORMAT)
    vault.set_secret("prod", "SOON", "v1", metadata={"expires_at": soon})
    vault.set_secret("prod", "FAR", "v2", metadata={"expires_at": far})
    results = list_expiring(vault, "prod", within_days=30)
    keys = [r.key for r in results]
    assert "SOON" in keys
    assert "FAR" not in keys


def test_list_expiring_includes_expired(vault):
    past = (datetime.now(timezone.utc) - timedelta(days=2)).strftime(EXPIRY_DATE_FORMAT)
    vault.set_secret("prod", "EXPIRED", "old", metadata={"expires_at": past})
    results = list_expiring(vault, "prod", within_days=30)
    assert any(r.key == "EXPIRED" for r in results)


def test_list_expiring_empty_env():
    empty = _FakeVault()
    assert list_expiring(empty, "staging") == []
