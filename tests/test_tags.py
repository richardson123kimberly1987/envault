"""Tests for envault.tags."""

from __future__ import annotations

from typing import Dict, List, Optional

import pytest

from envault.tags import TagError, TagResult, add_tag, list_by_tag, remove_tag


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str, tags: Optional[List[str]] = None) -> None:
        self._value = value
        self._tags: List[str] = tags or []

    def to_dict(self) -> Dict:
        return {"value": self._value, "tags": list(self._tags)}


class _FakeVault:
    def __init__(self) -> None:
        # {env: {key: _FakeEntry}}
        self._data: Dict[str, Dict[str, _FakeEntry]] = {}

    def get_secret(self, environment: str, key: str) -> Optional[_FakeEntry]:
        return self._data.get(environment, {}).get(key)

    def set_secret(
        self,
        environment: str,
        key: str,
        value: str,
        tags: Optional[List[str]] = None,
    ) -> None:
        self._data.setdefault(environment, {})[key] = _FakeEntry(value, tags)

    def list_environments(self) -> List[str]:
        return list(self._data.keys())

    def list_secrets(self, environment: str) -> List[str]:
        return list(self._data.get(environment, {}).keys())


# ---------------------------------------------------------------------------
# TagResult
# ---------------------------------------------------------------------------

def test_tag_result_to_dict():
    r = TagResult("prod", "DB_PASS", ["db", "critical"])
    d = r.to_dict()
    assert d == {"environment": "prod", "key": "DB_PASS", "tags": ["db", "critical"]}


# ---------------------------------------------------------------------------
# add_tag
# ---------------------------------------------------------------------------

def test_add_tag_attaches_tag():
    vault = _FakeVault()
    vault.set_secret("dev", "API_KEY", "secret", tags=[])
    add_tag(vault, "dev", "API_KEY", "infra")
    entry = vault.get_secret("dev", "API_KEY")
    assert "infra" in entry.to_dict()["tags"]


def test_add_tag_idempotent():
    vault = _FakeVault()
    vault.set_secret("dev", "API_KEY", "secret", tags=["infra"])
    add_tag(vault, "dev", "API_KEY", "infra")
    entry = vault.get_secret("dev", "API_KEY")
    assert entry.to_dict()["tags"].count("infra") == 1


def test_add_tag_missing_secret_raises():
    vault = _FakeVault()
    with pytest.raises(TagError, match="not found"):
        add_tag(vault, "dev", "MISSING", "infra")


# ---------------------------------------------------------------------------
# remove_tag
# ---------------------------------------------------------------------------

def test_remove_tag_removes_tag():
    vault = _FakeVault()
    vault.set_secret("dev", "TOKEN", "abc", tags=["infra", "legacy"])
    remove_tag(vault, "dev", "TOKEN", "legacy")
    entry = vault.get_secret("dev", "TOKEN")
    assert "legacy" not in entry.to_dict()["tags"]
    assert "infra" in entry.to_dict()["tags"]


def test_remove_tag_missing_secret_raises():
    vault = _FakeVault()
    with pytest.raises(TagError):
        remove_tag(vault, "dev", "GHOST", "infra")


# ---------------------------------------------------------------------------
# list_by_tag
# ---------------------------------------------------------------------------

def test_list_by_tag_returns_matching_secrets():
    vault = _FakeVault()
    vault.set_secret("prod", "DB_PASS", "x", tags=["db"])
    vault.set_secret("prod", "API_KEY", "y", tags=["infra"])
    vault.set_secret("staging", "DB_PASS", "z", tags=["db"])
    results = list_by_tag(vault, "db")
    keys = [(r.environment, r.key) for r in results]
    assert ("prod", "DB_PASS") in keys
    assert ("staging", "DB_PASS") in keys
    assert ("prod", "API_KEY") not in keys


def test_list_by_tag_filtered_by_environment():
    vault = _FakeVault()
    vault.set_secret("prod", "DB_PASS", "x", tags=["db"])
    vault.set_secret("staging", "DB_PASS", "z", tags=["db"])
    results = list_by_tag(vault, "db", environment="prod")
    assert all(r.environment == "prod" for r in results)
    assert len(results) == 1


def test_list_by_tag_empty_when_no_match():
    vault = _FakeVault()
    vault.set_secret("dev", "KEY", "v"])
    results = list_by_tag(vault, "nonexistent")
    assert results == []
