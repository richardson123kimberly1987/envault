"""Tests for envault.version module."""
from __future__ import annotations

import json
from typing import Any, Dict, Optional

import pytest

from envault.version import VersionError, bump_version, get_version, list_versions, VERSION_KEY


class _FakeEntry:
    def __init__(self, value: str) -> None:
        self._value = value

    def decrypt(self, passphrase: str = "") -> str:  # noqa: ARG002
        return self._value

    def to_dict(self) -> Dict[str, Any]:
        return {"value": self._value}


class _FakeVault:
    def __init__(self) -> None:
        self._store: Dict[str, Dict[str, Any]] = {}
        self.saved = False

    def get_secret(self, environment: str, secret: str) -> Optional[str]:
        return self._store.get(environment, {}).get(secret)

    def set_secret(self, environment: str, secret: str, value: Any) -> None:
        self._store.setdefault(environment, {})[secret] = value

    def save(self) -> None:
        self.saved = True


@pytest.fixture()
def vault() -> _FakeVault:
    v = _FakeVault()
    v.set_secret("production", "DB_PASS", "secret")
    v.set_secret("production", "API_KEY", "key123")
    return v


def test_get_version_default_zero(vault: _FakeVault) -> None:
    assert get_version(vault, "production", "DB_PASS") == 0


def test_bump_version_increments(vault: _FakeVault) -> None:
    result = bump_version(vault, "production", "DB_PASS")
    assert result.version == 1
    assert result.previous is None


def test_bump_version_twice(vault: _FakeVault) -> None:
    bump_version(vault, "production", "DB_PASS")
    result = bump_version(vault, "production", "DB_PASS")
    assert result.version == 2
    assert result.previous == 1


def test_bump_version_missing_secret_raises(vault: _FakeVault) -> None:
    with pytest.raises(VersionError, match="MISSING"):
        bump_version(vault, "production", "MISSING")


def test_get_version_after_bump(vault: _FakeVault) -> None:
    bump_version(vault, "production", "DB_PASS")
    assert get_version(vault, "production", "DB_PASS") == 1


def test_list_versions_empty(vault: _FakeVault) -> None:
    result = list_versions(vault, "production")
    assert result == []


def test_list_versions_after_bumps(vault: _FakeVault) -> None:
    bump_version(vault, "production", "DB_PASS")
    bump_version(vault, "production", "API_KEY")
    result = list_versions(vault, "production")
    secrets = {r["secret"] for r in result}
    assert secrets == {"DB_PASS", "API_KEY"}
    for r in result:
        assert r["version"] == 1
        assert r["environment"] == "production"


def test_list_versions_scoped_to_environment(vault: _FakeVault) -> None:
    vault.set_secret("staging", "DB_PASS", "other")
    bump_version(vault, "production", "DB_PASS")
    result = list_versions(vault, "staging")
    assert result == []


def test_version_result_to_dict(vault: _FakeVault) -> None:
    result = bump_version(vault, "production", "DB_PASS")
    d = result.to_dict()
    assert d["secret"] == "DB_PASS"
    assert d["environment"] == "production"
    assert d["version"] == 1
    assert d["previous"] is None
