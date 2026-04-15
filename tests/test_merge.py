"""Tests for envault.merge."""
from __future__ import annotations

import pytest

from envault.merge import MergeError, MergeResult, merge_environments


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str):
        self.value = value

    def to_dict(self):
        return {"value": self.value}


class _FakeVault:
    def __init__(self, envs: dict):
        # envs: {env_name: {key: value}}
        self._data: dict[str, dict[str, str]] = {
            env: dict(secrets) for env, secrets in envs.items()
        }

    def list_environments(self):
        return list(self._data.keys())

    def list_secrets(self, env: str):
        return list(self._data.get(env, {}).keys())

    def get_secret(self, env: str, key: str):
        val = self._data.get(env, {}).get(key)
        return _FakeEntry(val) if val is not None else None

    def set_secret(self, env: str, key: str, value: str):
        self._data.setdefault(env, {})[key] = value


# ---------------------------------------------------------------------------
# MergeResult.to_dict
# ---------------------------------------------------------------------------

def test_merge_result_to_dict():
    r = MergeResult("dev", "staging", merged=["A"], skipped=["B"], overwritten=["C"])
    d = r.to_dict()
    assert d["source_env"] == "dev"
    assert d["target_env"] == "staging"
    assert d["merged"] == ["A"]
    assert d["skipped"] == ["B"]
    assert d["overwritten"] == ["C"]


# ---------------------------------------------------------------------------
# Happy-path merges
# ---------------------------------------------------------------------------

def test_merge_new_keys():
    vault = _FakeVault({"dev": {"DB": "dev-db", "API": "dev-api"}, "staging": {}})
    result = merge_environments(vault, "dev", "staging")
    assert set(result.merged) == {"DB", "API"}
    assert result.skipped == []
    assert result.overwritten == []
    assert vault._data["staging"]["DB"] == "dev-db"


def test_merge_skips_existing_without_overwrite():
    vault = _FakeVault({"dev": {"DB": "dev-db"}, "staging": {"DB": "staging-db"}})
    result = merge_environments(vault, "dev", "staging", overwrite=False)
    assert result.skipped == ["DB"]
    assert result.merged == []
    assert vault._data["staging"]["DB"] == "staging-db"  # unchanged


def test_merge_overwrites_existing_when_flag_set():
    vault = _FakeVault({"dev": {"DB": "dev-db"}, "staging": {"DB": "staging-db"}})
    result = merge_environments(vault, "dev", "staging", overwrite=True)
    assert result.overwritten == ["DB"]
    assert vault._data["staging"]["DB"] == "dev-db"


def test_merge_with_key_filter():
    vault = _FakeVault({"dev": {"DB": "x", "API": "y"}, "staging": {}})
    result = merge_environments(vault, "dev", "staging", keys=["DB"])
    assert result.merged == ["DB"]
    assert "API" not in vault._data["staging"]


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------

def test_merge_missing_source_raises():
    vault = _FakeVault({"staging": {}})
    with pytest.raises(MergeError, match="Source environment"):
        merge_environments(vault, "dev", "staging")


def test_merge_missing_target_raises():
    vault = _FakeVault({"dev": {"DB": "x"}})
    with pytest.raises(MergeError, match="Target environment"):
        merge_environments(vault, "dev", "prod")


def test_merge_same_env_raises():
    vault = _FakeVault({"dev": {"DB": "x"}})
    with pytest.raises(MergeError, match="different"):
        merge_environments(vault, "dev", "dev")


def test_merge_missing_key_in_source_raises():
    vault = _FakeVault({"dev": {"DB": "x"}, "staging": {}})
    with pytest.raises(MergeError, match="Keys not found"):
        merge_environments(vault, "dev", "staging", keys=["MISSING"])
