"""Tests for envault.lock."""
import pytest

from envault.lock import (
    LockError,
    LockResult,
    lock_secret,
    unlock_secret,
    list_locked,
    is_locked,
)


class _FakeEntry:
    def __init__(self, value: str, locked: bool = False):
        self._data = {"value": value, "locked": locked}

    def to_dict(self):
        return dict(self._data)


class _FakeVault:
    def __init__(self):
        self._store: dict = {}

    def get_secret(self, env, key):
        return self._store.get((env, key))

    def set_secret(self, env, key, value, metadata=None):
        locked = (metadata or {}).get("locked", False)
        self._store[(env, key)] = _FakeEntry(value, locked=locked)

    def list_secrets(self, env):
        return [k for (e, k) in self._store if e == env]


@pytest.fixture
def vault():
    v = _FakeVault()
    v.set_secret("prod", "DB_PASS", "s3cr3t")
    v.set_secret("prod", "API_KEY", "abc123")
    return v


def test_lock_result_to_dict():
    r = LockResult(key="K", environment="E", locked=True, message="ok")
    d = r.to_dict()
    assert d == {"key": "K", "environment": "E", "locked": True, "message": "ok"}


def test_lock_secret_success(vault):
    result = lock_secret(vault, "prod", "DB_PASS")
    assert result.locked is True
    assert "locked" in result.message.lower()
    assert is_locked(vault, "prod", "DB_PASS")


def test_lock_secret_already_locked(vault):
    lock_secret(vault, "prod", "DB_PASS")
    result = lock_secret(vault, "prod", "DB_PASS")
    assert result.locked is True
    assert "already" in result.message


def test_lock_secret_missing_raises(vault):
    with pytest.raises(LockError, match="not found"):
        lock_secret(vault, "prod", "MISSING")


def test_unlock_secret_success(vault):
    lock_secret(vault, "prod", "DB_PASS")
    result = unlock_secret(vault, "prod", "DB_PASS")
    assert result.locked is False
    assert not is_locked(vault, "prod", "DB_PASS")


def test_unlock_secret_not_locked(vault):
    result = unlock_secret(vault, "prod", "DB_PASS")
    assert result.locked is False
    assert "not locked" in result.message


def test_unlock_secret_missing_raises(vault):
    with pytest.raises(LockError, match="not found"):
        unlock_secret(vault, "prod", "GHOST")


def test_list_locked_returns_only_locked(vault):
    lock_secret(vault, "prod", "DB_PASS")
    locked = list_locked(vault, "prod")
    assert "DB_PASS" in locked
    assert "API_KEY" not in locked


def test_list_locked_empty_when_none_locked(vault):
    assert list_locked(vault, "prod") == []


def test_is_locked_false_for_missing(vault):
    assert is_locked(vault, "prod", "NONEXISTENT") is False
