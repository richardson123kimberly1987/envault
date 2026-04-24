"""Tests for envault.alias."""
import pytest

from envault.alias import (
    AliasError,
    AliasResult,
    add_alias,
    remove_alias,
    resolve_alias,
)


# ---------------------------------------------------------------------------
# Fake vault helpers
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str):
        self._value = value

    def to_dict(self):
        return {"value": self._value}


class _FakeVault:
    def __init__(self):
        self._store: dict[tuple, _FakeEntry] = {}

    def get_secret(self, env, key):
        return self._store.get((env, key))

    def set_secret(self, env, key, value):
        self._store[(env, key)] = _FakeEntry(value)

    def delete_secret(self, env, key):
        self._store.pop((env, key), None)


# ---------------------------------------------------------------------------
# AliasResult.to_dict
# ---------------------------------------------------------------------------

def test_alias_result_to_dict():
    r = AliasResult(
        alias="db_url",
        target_key="DATABASE_URL",
        environment="prod",
        resolved_value="postgres://...",
        action="resolved",
    )
    d = r.to_dict()
    assert d["alias"] == "db_url"
    assert d["target_key"] == "DATABASE_URL"
    assert d["resolved_value"] == "postgres://..."
    assert d["action"] == "resolved"


# ---------------------------------------------------------------------------
# add_alias
# ---------------------------------------------------------------------------

def test_add_alias_creates_entry():
    vault = _FakeVault()
    vault.set_secret("prod", "DATABASE_URL", "postgres://host/db")

    result = add_alias(vault, "prod", "db_url", "DATABASE_URL")

    assert result.action == "created"
    assert result.alias == "db_url"
    assert result.target_key == "DATABASE_URL"

    stored = vault.get_secret("prod", "db_url")
    assert stored is not None
    assert stored.to_dict()["value"] == "__alias__:DATABASE_URL"


def test_add_alias_missing_target_raises():
    vault = _FakeVault()
    with pytest.raises(AliasError, match="not found"):
        add_alias(vault, "prod", "db_url", "DATABASE_URL")


def test_add_alias_duplicate_raises():
    vault = _FakeVault()
    vault.set_secret("prod", "DATABASE_URL", "postgres://host/db")
    add_alias(vault, "prod", "db_url", "DATABASE_URL")

    with pytest.raises(AliasError, match="already exists"):
        add_alias(vault, "prod", "db_url", "DATABASE_URL")


# ---------------------------------------------------------------------------
# remove_alias
# ---------------------------------------------------------------------------

def test_remove_alias_deletes_entry():
    vault = _FakeVault()
    vault.set_secret("prod", "DATABASE_URL", "postgres://host/db")
    add_alias(vault, "prod", "db_url", "DATABASE_URL")

    result = remove_alias(vault, "prod", "db_url")

    assert result.action == "removed"
    assert vault.get_secret("prod", "db_url") is None


def test_remove_alias_missing_raises():
    vault = _FakeVault()
    with pytest.raises(AliasError, match="not found"):
        remove_alias(vault, "prod", "db_url")


def test_remove_alias_on_real_secret_raises():
    vault = _FakeVault()
    vault.set_secret("prod", "DATABASE_URL", "postgres://host/db")
    with pytest.raises(AliasError, match="not an alias"):
        remove_alias(vault, "prod", "DATABASE_URL")


# ---------------------------------------------------------------------------
# resolve_alias
# ---------------------------------------------------------------------------

def test_resolve_alias_returns_target_value():
    vault = _FakeVault()
    vault.set_secret("prod", "DATABASE_URL", "postgres://host/db")
    add_alias(vault, "prod", "db_url", "DATABASE_URL")

    result = resolve_alias(vault, "prod", "db_url")

    assert result.action == "resolved"
    assert result.resolved_value == "postgres://host/db"
    assert result.target_key == "DATABASE_URL"


def test_resolve_alias_missing_raises():
    vault = _FakeVault()
    with pytest.raises(AliasError, match="not found"):
        resolve_alias(vault, "prod", "db_url")


def test_resolve_alias_broken_target_raises():
    vault = _FakeVault()
    vault.set_secret("prod", "DATABASE_URL", "postgres://host/db")
    add_alias(vault, "prod", "db_url", "DATABASE_URL")
    # Simulate target being deleted after alias creation.
    vault.delete_secret("prod", "DATABASE_URL")

    with pytest.raises(AliasError, match="missing secret"):
        resolve_alias(vault, "prod", "db_url")
