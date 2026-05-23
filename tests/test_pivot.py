"""Tests for envault.pivot."""
from __future__ import annotations

import pytest

from envault.pivot import PivotError, PivotEntry, PivotResult, pivot_environment


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
    def __init__(self, data: dict):
        # data = {env: {key: value}}
        self._data = data

    def list_secrets(self, env: str):
        return list(self._data.get(env, {}).keys())

    def get_secret(self, env: str, key: str):
        val = self._data.get(env, {}).get(key)
        if val is None:
            return None
        return _FakeEntry(val)


# ---------------------------------------------------------------------------
# PivotEntry / PivotResult unit tests
# ---------------------------------------------------------------------------

def test_pivot_entry_to_dict():
    entry = PivotEntry(value="secret", environments=["dev", "staging"])
    d = entry.to_dict()
    assert d["value"] == "secret"
    assert d["environments"] == ["dev", "staging"]


def test_pivot_result_to_dict():
    result = PivotResult(
        environment="dev",
        pivoted={"abc": PivotEntry(value="abc", environments=["dev"])},
        total=1,
    )
    d = result.to_dict()
    assert d["environment"] == "dev"
    assert d["total"] == 1
    assert "abc" in d["pivoted"]


# ---------------------------------------------------------------------------
# pivot_environment tests
# ---------------------------------------------------------------------------

def test_pivot_groups_by_value():
    vault = _FakeVault({"dev": {"KEY_A": "val1", "KEY_B": "val1", "KEY_C": "val2"}})
    result = pivot_environment(vault, "dev")
    assert result.total == 2
    assert "val1" in result.pivoted
    assert "val2" in result.pivoted
    assert set(result.pivoted["val1"].environments) == {"dev"}


def test_pivot_empty_environment_raises():
    vault = _FakeVault({"dev": {}})
    with pytest.raises(PivotError, match="No secrets found"):
        pivot_environment(vault, "dev")


def test_pivot_missing_environment_raises():
    vault = _FakeVault({})
    with pytest.raises(PivotError, match="No secrets found"):
        pivot_environment(vault, "staging")


def test_pivot_with_target_env_filters_mismatched():
    vault = _FakeVault({
        "dev": {"KEY_A": "same", "KEY_B": "different_dev"},
        "prod": {"KEY_A": "same", "KEY_B": "different_prod"},
    })
    result = pivot_environment(vault, "dev", target_env="prod")
    # KEY_B has different values -> excluded
    assert "same" in result.pivoted
    assert "different_dev" not in result.pivoted
    assert result.total == 1
    assert "prod" in result.pivoted["same"].environments


def test_pivot_with_target_env_key_missing_in_target():
    vault = _FakeVault({
        "dev": {"KEY_A": "val", "KEY_ONLY_DEV": "only"},
        "prod": {"KEY_A": "val"},
    })
    result = pivot_environment(vault, "dev", target_env="prod")
    # KEY_ONLY_DEV absent in prod -> excluded
    assert result.total == 1
    assert "val" in result.pivoted


def test_pivot_decrypt_error_raises():
    class _BadEntry:
        def decrypt(self):
            raise RuntimeError("bad key")

    class _BadVault:
        def list_secrets(self, env):
            return ["KEY"]
        def get_secret(self, env, key):
            return _BadEntry()

    with pytest.raises(PivotError, match="Failed to decrypt"):
        pivot_environment(_BadVault(), "dev")
