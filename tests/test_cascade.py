"""Tests for envault.cascade."""
from __future__ import annotations

import pytest

from envault.cascade import CascadeError, CascadeResult, cascade_all, cascade_secret


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str):
        self._value = value

    def to_dict(self):
        return {"value": self._value}


class _FakeVault:
    def __init__(self, data: dict | None = None):
        # data: {env: {name: value}}
        self._data: dict[str, dict[str, str]] = data or {}
        self.saved = False

    def get_secret(self, name, env):
        return _FakeEntry(self._data[env][name]) if (
            env in self._data and name in self._data[env]
        ) else None

    def set_secret(self, name, value, env):
        self._data.setdefault(env, {})[name] = value

    def list_secrets(self, env):
        return list(self._data.get(env, {}).keys())

    def save(self):
        self.saved = True


# ---------------------------------------------------------------------------
# cascade_secret
# ---------------------------------------------------------------------------

def test_cascade_secret_propagates_to_empty_targets():
    vault = _FakeVault({"prod": {"DB_URL": "postgres://prod"}})
    result = cascade_secret(vault, "DB_URL", "prod", ["staging", "dev"])
    assert result.propagated_to == ["staging", "dev"]
    assert result.skipped == []
    assert vault._data["staging"]["DB_URL"] == "postgres://prod"
    assert vault._data["dev"]["DB_URL"] == "postgres://prod"


def test_cascade_secret_skips_existing_without_overwrite():
    vault = _FakeVault({
        "prod": {"DB_URL": "postgres://prod"},
        "staging": {"DB_URL": "postgres://staging"},
    })
    result = cascade_secret(vault, "DB_URL", "prod", ["staging", "dev"])
    assert "staging" in result.skipped
    assert "dev" in result.propagated_to
    # staging value unchanged
    assert vault._data["staging"]["DB_URL"] == "postgres://staging"


def test_cascade_secret_overwrites_when_flag_set():
    vault = _FakeVault({
        "prod": {"DB_URL": "postgres://prod"},
        "staging": {"DB_URL": "postgres://staging"},
    })
    result = cascade_secret(vault, "DB_URL", "prod", ["staging"], overwrite=True)
    assert result.propagated_to == ["staging"]
    assert result.skipped == []
    assert vault._data["staging"]["DB_URL"] == "postgres://prod"


def test_cascade_secret_raises_when_source_missing():
    vault = _FakeVault({"prod": {}})
    with pytest.raises(CascadeError, match="not found"):
        cascade_secret(vault, "MISSING", "prod", ["staging"])


def test_cascade_result_to_dict():
    r = CascadeResult(
        source_env="prod",
        target_envs=["staging"],
        secret_name="KEY",
        propagated_to=["staging"],
        skipped=[],
        overwrite=False,
    )
    d = r.to_dict()
    assert d["source_env"] == "prod"
    assert d["propagated_to"] == ["staging"]
    assert d["overwrite"] is False


# ---------------------------------------------------------------------------
# cascade_all
# ---------------------------------------------------------------------------

def test_cascade_all_propagates_all_secrets():
    vault = _FakeVault({"prod": {"A": "1", "B": "2"}})
    results = cascade_all(vault, "prod", ["staging"])
    assert len(results) == 2
    assert vault._data["staging"]["A"] == "1"
    assert vault._data["staging"]["B"] == "2"


def test_cascade_all_empty_source_returns_empty_list():
    vault = _FakeVault({"prod": {}})
    results = cascade_all(vault, "prod", ["staging"])
    assert results == []
