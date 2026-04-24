"""Tests for envault.priority."""
from __future__ import annotations

from typing import Any

import pytest

from envault.priority import (
    PRIORITY_LEVELS,
    PriorityError,
    PriorityResult,
    get_priority,
    list_by_priority,
    set_priority,
)


class _FakeEntry:
    def __init__(self, value: str, metadata: dict | None = None):
        self._value = value
        self._metadata = metadata or {}

    def to_dict(self) -> dict[str, Any]:
        return {"value": self._value, "metadata": self._metadata}


class _FakeVault:
    def __init__(self):
        self._store: dict[tuple[str, str], _FakeEntry] = {}

    def get_secret(self, environment: str, key: str) -> _FakeEntry | None:
        return self._store.get((environment, key))

    def set_secret(self, environment: str, key: str, value: str, metadata: dict | None = None):
        self._store[(environment, key)] = _FakeEntry(value, metadata or {})

    def list_secrets(self, environment: str) -> list[str]:
        return [k for (env, k) in self._store if env == environment]


@pytest.fixture()
def vault():
    v = _FakeVault()
    v.set_secret("prod", "DB_PASS", "secret123", {})
    v.set_secret("prod", "API_KEY", "key456", {"priority": "high"})
    v.set_secret("prod", "LOG_LEVEL", "info", {"priority": "low"})
    return v


def test_priority_levels_constant_not_empty():
    assert len(PRIORITY_LEVELS) > 0
    assert "medium" in PRIORITY_LEVELS
    assert "critical" in PRIORITY_LEVELS


def test_priority_result_to_dict():
    result = PriorityResult(key="DB_PASS", environment="prod", priority="high")
    d = result.to_dict()
    assert d == {"key": "DB_PASS", "environment": "prod", "priority": "high"}


def test_set_priority_success(vault):
    result = set_priority(vault, "prod", "DB_PASS", "critical")
    assert result.priority == "critical"
    assert result.key == "DB_PASS"
    assert result.environment == "prod"


def test_set_priority_invalid_level_raises(vault):
    with pytest.raises(PriorityError, match="Invalid priority"):
        set_priority(vault, "prod", "DB_PASS", "urgent")


def test_set_priority_missing_secret_raises(vault):
    with pytest.raises(PriorityError, match="not found"):
        set_priority(vault, "prod", "MISSING_KEY", "high")


def test_get_priority_existing(vault):
    result = get_priority(vault, "prod", "API_KEY")
    assert result.priority == "high"


def test_get_priority_defaults_to_medium(vault):
    result = get_priority(vault, "prod", "DB_PASS")
    assert result.priority == "medium"


def test_get_priority_missing_secret_raises(vault):
    with pytest.raises(PriorityError, match="not found"):
        get_priority(vault, "prod", "NONEXISTENT")


def test_list_by_priority_returns_matching(vault):
    results = list_by_priority(vault, "prod", "high")
    keys = [r.key for r in results]
    assert "API_KEY" in keys
    assert "DB_PASS" not in keys


def test_list_by_priority_invalid_level_raises(vault):
    with pytest.raises(PriorityError, match="Invalid priority"):
        list_by_priority(vault, "prod", "extreme")


def test_list_by_priority_empty_when_none_match(vault):
    results = list_by_priority(vault, "prod", "critical")
    assert results == []
