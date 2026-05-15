"""Tests for envault.shadow."""
from __future__ import annotations

import pytest

from envault.shadow import (
    ShadowError,
    ShadowResult,
    capture_shadow,
    clear_shadow,
    get_shadow,
)


class _FakeEntry:
    def __init__(self, value: str, metadata: dict | None = None):
        self._value = value
        self._meta = metadata or {}

    def decrypt(self) -> str:
        return self._value

    def update_value(self, value: str, metadata: dict | None = None) -> None:
        self._value = value
        if metadata is not None:
            self._meta = metadata

    def to_dict(self) -> dict:
        return {"value": self._value, "metadata": self._meta}


class _FakeVault:
    def __init__(self, entries: dict[tuple[str, str], _FakeEntry] | None = None):
        self._entries = entries or {}
        self.saved = False

    def get_secret(self, environment: str, secret: str) -> _FakeEntry | None:
        return self._entries.get((environment, secret))

    def save(self) -> None:
        self.saved = True


def _vault_with(env: str, key: str, value: str, meta: dict | None = None) -> _FakeVault:
    entry = _FakeEntry(value, meta)
    return _FakeVault({(env, key): entry})


# --- capture_shadow ---

def test_capture_shadow_stores_current_as_previous():
    vault = _vault_with("prod", "DB_PASS", "secret123")
    result = capture_shadow(vault, "prod", "DB_PASS")
    assert result.current_value == "secret123"
    assert result.previous_value is None
    assert result.had_shadow is False
    assert vault.saved


def test_capture_shadow_overwrites_existing_shadow():
    vault = _vault_with("prod", "DB_PASS", "newval", {"__shadow__": "oldval"})
    result = capture_shadow(vault, "prod", "DB_PASS")
    assert result.previous_value == "oldval"
    assert result.had_shadow is True
    assert result.current_value == "newval"


def test_capture_shadow_missing_secret_raises():
    vault = _FakeVault()
    with pytest.raises(ShadowError, match="not found"):
        capture_shadow(vault, "prod", "MISSING")


# --- get_shadow ---

def test_get_shadow_returns_previous_value():
    vault = _vault_with("dev", "API_KEY", "current", {"__shadow__": "previous"})
    result = get_shadow(vault, "dev", "API_KEY")
    assert result.previous_value == "previous"
    assert result.current_value == "current"
    assert result.had_shadow is True


def test_get_shadow_no_shadow_returns_none():
    vault = _vault_with("dev", "API_KEY", "current")
    result = get_shadow(vault, "dev", "API_KEY")
    assert result.previous_value is None
    assert result.had_shadow is False


def test_get_shadow_missing_secret_raises():
    vault = _FakeVault()
    with pytest.raises(ShadowError):
        get_shadow(vault, "dev", "NOPE")


# --- clear_shadow ---

def test_clear_shadow_removes_previous_value():
    vault = _vault_with("staging", "TOKEN", "val", {"__shadow__": "old"})
    result = clear_shadow(vault, "staging", "TOKEN")
    assert result.had_shadow is True
    assert result.previous_value == "old"
    assert vault.saved


def test_clear_shadow_no_shadow_is_noop():
    vault = _vault_with("staging", "TOKEN", "val")
    result = clear_shadow(vault, "staging", "TOKEN")
    assert result.had_shadow is False
    assert result.previous_value is None


# --- ShadowResult.to_dict ---

def test_shadow_result_to_dict():
    r = ShadowResult(
        secret="KEY",
        environment="prod",
        previous_value="old",
        current_value="new",
        had_shadow=True,
    )
    d = r.to_dict()
    assert d["secret"] == "KEY"
    assert d["environment"] == "prod"
    assert d["previous_value"] == "old"
    assert d["current_value"] == "new"
    assert d["had_shadow"] is True
