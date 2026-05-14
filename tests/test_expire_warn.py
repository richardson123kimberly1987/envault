"""Tests for envault.expire_warn."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from envault.expire_warn import (
    ExpireWarnError,
    ExpireWarnResult,
    check_expiry_warning,
    check_all_expiry_warnings,
    EXPIRE_WARN_EVENTS,
)


class _FakeEntry:
    def __init__(self, expires_at=None):
        self._expires_at = expires_at

    def to_dict(self):
        return {"expires_at": self._expires_at}


class _FakeVault:
    def __init__(self, secrets):
        self._secrets = secrets  # {(env, key): _FakeEntry}

    def get_secret(self, environment, key):
        return self._secrets.get((environment, key))

    def list_secrets(self, environment):
        return [k for (e, k) in self._secrets if e == environment]


def _future(days=30):
    return (datetime.now(tz=timezone.utc) + timedelta(days=days)).isoformat()


def _past(days=1):
    return (datetime.now(tz=timezone.utc) - timedelta(days=days)).isoformat()


def test_expire_warn_events_not_empty():
    assert len(EXPIRE_WARN_EVENTS) >= 2


def test_check_missing_secret_raises():
    vault = _FakeVault({})
    with pytest.raises(ExpireWarnError, match="not found"):
        check_expiry_warning(vault, "prod", "MISSING_KEY")


def test_check_no_expiry_returns_ok():
    vault = _FakeVault({("prod", "API_KEY"): _FakeEntry(expires_at=None)})
    result = check_expiry_warning(vault, "prod", "API_KEY")
    assert not result.is_expired
    assert not result.warning
    assert result.days_remaining is None
    assert result.expires_at is None


def test_check_far_future_no_warning():
    vault = _FakeVault({("prod", "API_KEY"): _FakeEntry(expires_at=_future(30))})
    result = check_expiry_warning(vault, "prod", "API_KEY", threshold_days=7)
    assert not result.is_expired
    assert not result.warning
    assert result.days_remaining >= 29


def test_check_within_threshold_warns():
    vault = _FakeVault({("prod", "API_KEY"): _FakeEntry(expires_at=_future(3))})
    result = check_expiry_warning(vault, "prod", "API_KEY", threshold_days=7)
    assert not result.is_expired
    assert result.warning
    assert 0 <= result.days_remaining <= 3


def test_check_expired_secret():
    vault = _FakeVault({("prod", "API_KEY"): _FakeEntry(expires_at=_past(2))})
    result = check_expiry_warning(vault, "prod", "API_KEY")
    assert result.is_expired
    assert not result.warning
    assert result.days_remaining < 0


def test_result_to_dict_keys():
    r = ExpireWarnResult(
        key="K", environment="e", expires_at=None,
        days_remaining=None, is_expired=False, warning=False
    )
    d = r.to_dict()
    assert set(d.keys()) == {"key", "environment", "expires_at", "days_remaining", "is_expired", "warning"}


def test_check_all_returns_only_warnings():
    vault = _FakeVault({
        ("prod", "A"): _FakeEntry(expires_at=_future(3)),
        ("prod", "B"): _FakeEntry(expires_at=_future(30)),
        ("prod", "C"): _FakeEntry(expires_at=_past(1)),
    })
    results = check_all_expiry_warnings(vault, "prod", threshold_days=7)
    keys = {r.key for r in results}
    assert "A" in keys
    assert "C" in keys
    assert "B" not in keys


def test_check_all_empty_when_no_warnings():
    vault = _FakeVault({("prod", "X"): _FakeEntry(expires_at=_future(30))})
    results = check_all_expiry_warnings(vault, "prod", threshold_days=7)
    assert results == []
