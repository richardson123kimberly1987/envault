"""Tests for envault.suffix module."""
from __future__ import annotations

import pytest

from envault.suffix import (
    SuffixError,
    SuffixResult,
    add_suffix,
    remove_suffix,
    list_with_suffix,
)


class _FakeEntry:
    def __init__(self, value: str):
        self._value = value

    def decrypt(self) -> str:
        return self._value

    def to_dict(self) -> dict:
        return {"value": self._value}


class _FakeVault:
    def __init__(self):
        self._store: dict[str, dict[str, _FakeEntry]] = {}

    def get_secret(self, env: str, key: str):
        return self._store.get(env, {}).get(key)

    def set_secret(self, env: str, key: str, value: str):
        self._store.setdefault(env, {})[key] = _FakeEntry(value)

    def delete_secret(self, env: str, key: str):
        self._store.get(env, {}).pop(key, None)

    def list_secrets(self, env: str):
        return list(self._store.get(env, {}).keys())


@pytest.fixture()
def vault():
    v = _FakeVault()
    v.set_secret("prod", "DB_URL", "postgres://localhost")
    v.set_secret("prod", "API_KEY", "secret123")
    v.set_secret("prod", "CACHE_URL_OLD", "redis://localhost")
    return v


def test_suffix_result_to_dict():
    r = SuffixResult(
        secret="DB_URL_BKP",
        environment="prod",
        old_key="DB_URL",
        new_key="DB_URL_BKP",
        suffix="_BKP",
    )
    d = r.to_dict()
    assert d["old_key"] == "DB_URL"
    assert d["new_key"] == "DB_URL_BKP"
    assert d["suffix"] == "_BKP"
    assert d["removed"] is False


def test_add_suffix_renames_secret(vault):
    result = add_suffix(vault, "prod", "DB_URL", "_BKP")
    assert result.new_key == "DB_URL_BKP"
    assert result.old_key == "DB_URL"
    assert vault.get_secret("prod", "DB_URL_BKP") is not None
    assert vault.get_secret("prod", "DB_URL") is None


def test_add_suffix_preserves_value(vault):
    add_suffix(vault, "prod", "DB_URL", "_BKP")
    entry = vault.get_secret("prod", "DB_URL_BKP")
    assert entry.decrypt() == "postgres://localhost"


def test_add_suffix_missing_secret_raises(vault):
    with pytest.raises(SuffixError, match="not found"):
        add_suffix(vault, "prod", "MISSING", "_BKP")


def test_add_suffix_empty_suffix_raises(vault):
    with pytest.raises(SuffixError, match="empty"):
        add_suffix(vault, "prod", "DB_URL", "")


def test_add_suffix_conflict_raises(vault):
    vault.set_secret("prod", "DB_URL_BKP", "already_here")
    with pytest.raises(SuffixError, match="already exists"):
        add_suffix(vault, "prod", "DB_URL", "_BKP")


def test_remove_suffix_renames_secret(vault):
    result = remove_suffix(vault, "prod", "CACHE_URL_OLD", "_OLD")
    assert result.new_key == "CACHE_URL"
    assert result.removed is True
    assert vault.get_secret("prod", "CACHE_URL") is not None
    assert vault.get_secret("prod", "CACHE_URL_OLD") is None


def test_remove_suffix_not_ending_raises(vault):
    with pytest.raises(SuffixError, match="does not end with"):
        remove_suffix(vault, "prod", "DB_URL", "_OLD")


def test_remove_suffix_empty_suffix_raises(vault):
    with pytest.raises(SuffixError, match="empty"):
        remove_suffix(vault, "prod", "CACHE_URL_OLD", "")


def test_remove_suffix_empty_result_raises():
    v = _FakeVault()
    v.set_secret("prod", "_BKP", "val")
    with pytest.raises(SuffixError, match="empty key"):
        remove_suffix(v, "prod", "_BKP", "_BKP")


def test_list_with_suffix(vault):
    vault.set_secret("prod", "SECRET_OLD", "x")
    result = list_with_suffix(vault, "prod", "_OLD")
    assert "CACHE_URL_OLD" in result
    assert "SECRET_OLD" in result
    assert "DB_URL" not in result


def test_list_with_suffix_empty(vault):
    result = list_with_suffix(vault, "prod", "_NOPE")
    assert result == []
