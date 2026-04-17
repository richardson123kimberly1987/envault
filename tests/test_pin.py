"""Tests for envault.pin."""
import pytest
from envault.pin import pin_secret, unpin_secret, list_pinned, PinError, PinResult


class _FakeEntry:
    def __init__(self, value, meta=None):
        self._value = value
        self._meta = meta or {}

    def to_dict(self):
        return {"value": self._value, "meta": self._meta}


class _FakeVault:
    def __init__(self):
        self._store: dict = {}

    def get_secret(self, env, key):
        return self._store.get((env, key))

    def set_secret(self, env, key, value, meta=None):
        self._store[(env, key)] = _FakeEntry(value, meta or {})

    def list_secrets(self, env):
        return [k for (e, k) in self._store if e == env]

    def save(self):
        pass


@pytest.fixture
def vault():
    v = _FakeVault()
    v.set_secret("prod", "DB_PASS", "s3cr3t")
    v.set_secret("prod", "API_KEY", "abc123")
    return v


def test_pin_secret_returns_pin_result(vault):
    result = pin_secret(vault, "prod", "DB_PASS", "v1.2.3")
    assert isinstance(result, PinResult)
    assert result.pinned is True
    assert result.version == "v1.2.3"
    assert result.key == "DB_PASS"


def test_pin_secret_missing_key_raises(vault):
    with pytest.raises(PinError, match="not found"):
        pin_secret(vault, "prod", "MISSING", "v1")


def test_unpin_secret_clears_pin(vault):
    pin_secret(vault, "prod", "DB_PASS", "v1")
    result = unpin_secret(vault, "prod", "DB_PASS")
    assert result.pinned is False
    assert result.version is None


def test_unpin_missing_key_raises(vault):
    with pytest.raises(PinError):
        unpin_secret(vault, "prod", "GHOST")


def test_list_pinned_returns_only_pinned(vault):
    pin_secret(vault, "prod", "DB_PASS", "v2")
    results = list_pinned(vault, "prod")
    keys = [r.key for r in results]
    assert "DB_PASS" in keys
    assert "API_KEY" not in keys


def test_list_pinned_empty_when_none_pinned(vault):
    assert list_pinned(vault, "prod") == []


def test_pin_result_to_dict():
    r = PinResult(key="K", environment="e", pinned=True, version="v3")
    d = r.to_dict()
    assert d == {"key": "K", "environment": "e", "pinned": True, "version": "v3"}
