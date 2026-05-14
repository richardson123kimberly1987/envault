"""Tests for envault.prefix."""
from __future__ import annotations

import pytest

from envault.prefix import (
    PrefixError,
    PrefixResult,
    add_prefix,
    remove_prefix,
    list_prefixed,
)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str):
        self._value = value

    def decrypt(self) -> str:
        return self._value

    def to_dict(self) -> dict:
        return {"value": self._value}


class _FakeVault:
    def __init__(self, data: dict | None = None):
        # data = {env: {name: value}}
        self._data: dict[str, dict[str, str]] = data or {}

    def get_secret(self, environment: str, secret: str):
        return (
            _FakeEntry(self._data[environment][secret])
            if environment in self._data and secret in self._data[environment]
            else None
        )

    def set_secret(self, environment: str, secret: str, value: str):
        self._data.setdefault(environment, {})[secret] = value

    def delete_secret(self, environment: str, secret: str):
        self._data.get(environment, {}).pop(secret, None)

    def list_secrets(self, environment: str):
        return list(self._data.get(environment, {}).keys())


# ---------------------------------------------------------------------------
# PrefixResult
# ---------------------------------------------------------------------------

def test_prefix_result_to_dict():
    r = PrefixResult(
        secret="APP_KEY",
        environment="prod",
        old_name="KEY",
        new_name="APP_KEY",
        action="add",
    )
    d = r.to_dict()
    assert d["old_name"] == "KEY"
    assert d["new_name"] == "APP_KEY"
    assert d["action"] == "add"


# ---------------------------------------------------------------------------
# add_prefix
# ---------------------------------------------------------------------------

def test_add_prefix_renames_secret():
    vault = _FakeVault({"dev": {"KEY": "secret123"}})
    result = add_prefix(vault, "dev", "KEY", "APP_")
    assert result.new_name == "APP_KEY"
    assert result.old_name == "KEY"
    assert result.action == "add"
    assert vault.get_secret("dev", "APP_KEY") is not None
    assert vault.get_secret("dev", "KEY") is None


def test_add_prefix_missing_secret_raises():
    vault = _FakeVault({"dev": {}})
    with pytest.raises(PrefixError, match="not found"):
        add_prefix(vault, "dev", "MISSING", "APP_")


def test_add_prefix_empty_prefix_raises():
    vault = _FakeVault({"dev": {"KEY": "val"}})
    with pytest.raises(PrefixError, match="empty"):
        add_prefix(vault, "dev", "KEY", "")


def test_add_prefix_conflict_raises():
    vault = _FakeVault({"dev": {"KEY": "val", "APP_KEY": "other"}})
    with pytest.raises(PrefixError, match="already exists"):
        add_prefix(vault, "dev", "KEY", "APP_")


# ---------------------------------------------------------------------------
# remove_prefix
# ---------------------------------------------------------------------------

def test_remove_prefix_renames_secret():
    vault = _FakeVault({"prod": {"APP_KEY": "s3cr3t"}})
    result = remove_prefix(vault, "prod", "APP_KEY", "APP_")
    assert result.new_name == "KEY"
    assert result.old_name == "APP_KEY"
    assert result.action == "remove"
    assert vault.get_secret("prod", "KEY") is not None
    assert vault.get_secret("prod", "APP_KEY") is None


def test_remove_prefix_not_present_raises():
    vault = _FakeVault({"prod": {"KEY": "val"}})
    with pytest.raises(PrefixError, match="does not start with"):
        remove_prefix(vault, "prod", "KEY", "APP_")


def test_remove_prefix_empty_result_raises():
    vault = _FakeVault({"prod": {"APP_": "val"}})
    with pytest.raises(PrefixError, match="empty secret name"):
        remove_prefix(vault, "prod", "APP_", "APP_")


# ---------------------------------------------------------------------------
# list_prefixed
# ---------------------------------------------------------------------------

def test_list_prefixed_returns_matching():
    vault = _FakeVault({"staging": {"APP_KEY": "a", "APP_TOKEN": "b", "OTHER": "c"}})
    names = list_prefixed(vault, "staging", "APP_")
    assert set(names) == {"APP_KEY", "APP_TOKEN"}


def test_list_prefixed_empty_when_no_match():
    vault = _FakeVault({"staging": {"KEY": "a", "TOKEN": "b"}})
    assert list_prefixed(vault, "staging", "APP_") == []


def test_list_prefixed_missing_environment_returns_empty():
    vault = _FakeVault({})
    assert list_prefixed(vault, "nonexistent", "X_") == []
