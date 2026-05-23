"""Tests for envault.flatten."""
from __future__ import annotations

import pytest

from envault.flatten import FlattenError, FlattenResult, flatten_environments


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
        # data = {env: {key: value_str}}
        self._data: dict = {env: dict(keys) for env, keys in data.items()}

    def list_secrets(self, env: str):
        return list(self._data.get(env, {}).keys())

    def get_secret(self, env: str, key: str):
        val = self._data.get(env, {}).get(key)
        if val is None:
            return None
        return _FakeEntry(val)

    def set_secret(self, env: str, key: str, value: str):
        self._data.setdefault(env, {})[key] = value


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_flatten_result_to_dict():
    r = FlattenResult(
        source_envs=["dev", "staging"],
        target_env="prod",
        keys_merged=["DB_URL"],
        keys_skipped=[],
        overwrite=False,
    )
    d = r.to_dict()
    assert d["target_env"] == "prod"
    assert d["keys_merged"] == ["DB_URL"]
    assert d["overwrite"] is False


def test_flatten_empty_source_raises():
    vault = _FakeVault({})
    with pytest.raises(FlattenError, match="source_envs"):
        flatten_environments(vault, [], "prod")


def test_flatten_blank_target_raises():
    vault = _FakeVault({})
    with pytest.raises(FlattenError, match="target_env"):
        flatten_environments(vault, ["dev"], "   ")


def test_flatten_merges_disjoint_keys():
    vault = _FakeVault({
        "dev": {"DB_URL": "postgres://dev", "PORT": "5432"},
        "staging": {"API_KEY": "abc123"},
    })
    result = flatten_environments(vault, ["dev", "staging"], "prod")
    assert set(result.keys_merged) == {"DB_URL", "PORT", "API_KEY"}
    assert result.keys_skipped == []
    assert vault.get_secret("prod", "API_KEY").decrypt() == "abc123"


def test_flatten_no_overwrite_skips_duplicate_keys():
    vault = _FakeVault({
        "dev": {"SECRET": "dev-value"},
        "staging": {"SECRET": "staging-value"},
    })
    result = flatten_environments(vault, ["dev", "staging"], "prod", overwrite=False)
    assert "SECRET" in result.keys_merged
    assert "SECRET" in result.keys_skipped
    assert vault.get_secret("prod", "SECRET").decrypt() == "dev-value"


def test_flatten_overwrite_uses_last_source():
    vault = _FakeVault({
        "dev": {"SECRET": "dev-value"},
        "staging": {"SECRET": "staging-value"},
    })
    result = flatten_environments(vault, ["dev", "staging"], "prod", overwrite=True)
    assert "SECRET" in result.keys_merged
    assert vault.get_secret("prod", "SECRET").decrypt() == "staging-value"


def test_flatten_source_envs_recorded_in_result():
    vault = _FakeVault({"a": {"K": "v"}})
    result = flatten_environments(vault, ["a"], "b")
    assert result.source_envs == ["a"]
    assert result.target_env == "b"
