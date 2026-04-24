"""Tests for envault.deprecate."""
from __future__ import annotations

import pytest

from envault.deprecate import (
    DeprecateError,
    DeprecateResult,
    deprecate_secret,
    undeprecate_secret,
    list_deprecated,
    DEPRECATION_KEY,
    REPLACEMENT_KEY,
)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str, metadata: dict | None = None):
        self._value = value
        self._meta = metadata or {}

    def to_dict(self) -> dict:
        return {"value": self._value, **self._meta}


class _FakeVault:
    def __init__(self):
        self._store: dict[tuple, _FakeEntry] = {}

    def get_secret(self, env: str, name: str) -> _FakeEntry | None:
        return self._store.get((env, name))

    def set_secret(self, env: str, name: str, value: str, metadata: dict | None = None):
        self._store[(env, name)] = _FakeEntry(value, metadata)

    def list_secrets(self, env: str) -> list[str]:
        return [k[1] for k in self._store if k[0] == env]


# ---------------------------------------------------------------------------
# DeprecateResult.to_dict
# ---------------------------------------------------------------------------

def test_deprecate_result_to_dict():
    r = DeprecateResult(
        environment="prod",
        secret="API_KEY",
        deprecated=True,
        replacement="NEW_API_KEY",
        timestamp="2024-01-01T00:00:00+00:00",
    )
    d = r.to_dict()
    assert d["environment"] == "prod"
    assert d["secret"] == "API_KEY"
    assert d["deprecated"] is True
    assert d["replacement"] == "NEW_API_KEY"
    assert "timestamp" in d


# ---------------------------------------------------------------------------
# deprecate_secret
# ---------------------------------------------------------------------------

def test_deprecate_secret_returns_result():
    vault = _FakeVault()
    vault.set_secret("prod", "OLD_KEY", "s3cr3t")
    result = deprecate_secret(vault, "prod", "OLD_KEY", replacement="NEW_KEY")
    assert isinstance(result, DeprecateResult)
    assert result.deprecated is True
    assert result.replacement == "NEW_KEY"


def test_deprecate_secret_persists_flag():
    vault = _FakeVault()
    vault.set_secret("prod", "OLD_KEY", "s3cr3t")
    deprecate_secret(vault, "prod", "OLD_KEY")
    entry = vault.get_secret("prod", "OLD_KEY")
    assert entry.to_dict().get(DEPRECATION_KEY) is True


def test_deprecate_secret_missing_raises():
    vault = _FakeVault()
    with pytest.raises(DeprecateError, match="not found"):
        deprecate_secret(vault, "prod", "GHOST")


# ---------------------------------------------------------------------------
# undeprecate_secret
# ---------------------------------------------------------------------------

def test_undeprecate_secret_clears_flag():
    vault = _FakeVault()
    vault.set_secret("prod", "OLD_KEY", "s3cr3t")
    deprecate_secret(vault, "prod", "OLD_KEY", replacement="NEW_KEY")
    result = undeprecate_secret(vault, "prod", "OLD_KEY")
    assert result.deprecated is False
    assert result.replacement is None
    entry = vault.get_secret("prod", "OLD_KEY")
    assert DEPRECATION_KEY not in entry.to_dict()
    assert REPLACEMENT_KEY not in entry.to_dict()


def test_undeprecate_secret_missing_raises():
    vault = _FakeVault()
    with pytest.raises(DeprecateError, match="not found"):
        undeprecate_secret(vault, "prod", "GHOST")


# ---------------------------------------------------------------------------
# list_deprecated
# ---------------------------------------------------------------------------

def test_list_deprecated_returns_only_deprecated():
    vault = _FakeVault()
    vault.set_secret("prod", "OLD_KEY", "val1")
    vault.set_secret("prod", "ACTIVE_KEY", "val2")
    deprecate_secret(vault, "prod", "OLD_KEY", replacement="NEW_KEY")
    results = list_deprecated(vault, "prod")
    names = [r.secret for r in results]
    assert "OLD_KEY" in names
    assert "ACTIVE_KEY" not in names


def test_list_deprecated_empty_when_none():
    vault = _FakeVault()
    vault.set_secret("prod", "ACTIVE_KEY", "val")
    assert list_deprecated(vault, "prod") == []


def test_list_deprecated_includes_replacement():
    vault = _FakeVault()
    vault.set_secret("staging", "OLD", "x")
    deprecate_secret(vault, "staging", "OLD", replacement="NEW")
    results = list_deprecated(vault, "staging")
    assert results[0].replacement == "NEW"
