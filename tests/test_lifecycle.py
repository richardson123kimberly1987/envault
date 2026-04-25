"""Tests for envault.lifecycle."""
from __future__ import annotations

import pytest

from envault.lifecycle import (
    LIFECYCLE_STAGES,
    LifecycleError,
    LifecycleResult,
    get_stage,
    list_by_stage,
    set_stage,
)


class _FakeEntry:
    def __init__(self, value: str, stage: str = "active"):
        self._data = {"value": value, "lifecycle_stage": stage}

    def to_dict(self):
        return dict(self._data)


class _FakeVault:
    def __init__(self):
        self._store: dict[tuple, _FakeEntry] = {}
        self._saved: list = []

    def get_secret(self, env, name):
        return self._store.get((env, name))

    def set_secret(self, env, name, value, metadata=None):
        stage = (metadata or {}).get("lifecycle_stage", "active")
        self._store[(env, name)] = _FakeEntry(value, stage)
        self._saved.append((env, name, value))

    def list_secrets(self, env):
        return [k[1] for k in self._store if k[0] == env]


@pytest.fixture
def vault():
    v = _FakeVault()
    v.set_secret("prod", "API_KEY", "abc123")
    v.set_secret("prod", "DB_PASS", "secret", metadata={"lifecycle_stage": "deprecated"})
    return v


def test_lifecycle_stages_constant_not_empty():
    assert len(LIFECYCLE_STAGES) > 0
    assert "active" in LIFECYCLE_STAGES
    assert "expired" in LIFECYCLE_STAGES


def test_set_stage_returns_result(vault):
    result = set_stage(vault, "prod", "API_KEY", "inactive")
    assert isinstance(result, LifecycleResult)
    assert result.current_stage == "inactive"
    assert result.previous_stage == "active"
    assert result.secret == "API_KEY"
    assert result.environment == "prod"


def test_set_stage_to_dict(vault):
    result = set_stage(vault, "prod", "API_KEY", "deprecated")
    d = result.to_dict()
    assert d["current_stage"] == "deprecated"
    assert "changed_at" in d


def test_set_stage_invalid_raises(vault):
    with pytest.raises(LifecycleError, match="Invalid stage"):
        set_stage(vault, "prod", "API_KEY", "unknown")


def test_set_stage_missing_secret_raises(vault):
    with pytest.raises(LifecycleError, match="not found"):
        set_stage(vault, "prod", "MISSING", "active")


def test_get_stage_default_active(vault):
    assert get_stage(vault, "prod", "API_KEY") == "active"


def test_get_stage_deprecated(vault):
    assert get_stage(vault, "prod", "DB_PASS") == "deprecated"


def test_get_stage_missing_raises(vault):
    with pytest.raises(LifecycleError):
        get_stage(vault, "prod", "NOPE")


def test_list_by_stage_returns_matching(vault):
    names = list_by_stage(vault, "prod", "deprecated")
    assert "DB_PASS" in names
    assert "API_KEY" not in names


def test_list_by_stage_active(vault):
    names = list_by_stage(vault, "prod", "active")
    assert "API_KEY" in names


def test_list_by_stage_invalid_raises(vault):
    with pytest.raises(LifecycleError, match="Invalid stage"):
        list_by_stage(vault, "prod", "bogus")


def test_set_stage_persists(vault):
    set_stage(vault, "prod", "API_KEY", "archived")
    assert get_stage(vault, "prod", "API_KEY") == "archived"
