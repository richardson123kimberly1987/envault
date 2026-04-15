"""Tests for envault.compare."""
from __future__ import annotations

from typing import Dict, List, Optional

import pytest

from envault.compare import CompareError, CompareResult, compare_all, compare_secret


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, encrypted_value: str):
        self.encrypted_value = encrypted_value

    def to_dict(self):
        return {"encrypted_value": self.encrypted_value}


class _FakeVault:
    def __init__(self, data: Dict[str, Dict[str, _FakeEntry]]):
        # data[env][key] = entry
        self._data = data

    def get_secret(self, key: str, env: str) -> Optional[_FakeEntry]:
        return self._data.get(env, {}).get(key)

    def list_secrets(self, env: str) -> List[str]:
        return list(self._data.get(env, {}).keys())


# We bypass real crypto by patching decrypt to return the stored value as-is.
@pytest.fixture(autouse=True)
def patch_decrypt(monkeypatch):
    monkeypatch.setattr(
        "envault.compare.decrypt",
        lambda ciphertext, passphrase: ciphertext,
    )


# ---------------------------------------------------------------------------
# CompareResult.to_dict
# ---------------------------------------------------------------------------

def test_compare_result_to_dict():
    result = CompareResult(
        key="DB_URL",
        environments={"prod": "val1", "staging": "val2"},
        status="mismatch",
    )
    d = result.to_dict()
    assert d["key"] == "DB_URL"
    assert d["status"] == "mismatch"
    assert d["environments"] == {"prod": "val1", "staging": "val2"}


# ---------------------------------------------------------------------------
# compare_secret
# ---------------------------------------------------------------------------

def test_compare_secret_match():
    vault = _FakeVault({"prod": {"KEY": _FakeEntry("same")}, "staging": {"KEY": _FakeEntry("same")}})
    result = compare_secret(vault, "KEY", ["prod", "staging"], "pass")
    assert result.status == "match"
    assert result.environments == {"prod": "same", "staging": "same"}


def test_compare_secret_mismatch():
    vault = _FakeVault({"prod": {"KEY": _FakeEntry("a")}, "staging": {"KEY": _FakeEntry("b")}})
    result = compare_secret(vault, "KEY", ["prod", "staging"], "pass")
    assert result.status == "mismatch"


def test_compare_secret_missing_in_one_env():
    vault = _FakeVault({"prod": {"KEY": _FakeEntry("a")}, "staging": {}})
    result = compare_secret(vault, "KEY", ["prod", "staging"], "pass")
    assert result.status == "missing"
    assert result.environments["staging"] is None


def test_compare_secret_requires_two_envs():
    vault = _FakeVault({})
    with pytest.raises(CompareError):
        compare_secret(vault, "KEY", ["prod"], "pass")


def test_compare_secret_empty_envs_raises():
    vault = _FakeVault({})
    with pytest.raises(CompareError):
        compare_secret(vault, "KEY", [], "pass")


# ---------------------------------------------------------------------------
# compare_all
# ---------------------------------------------------------------------------

def test_compare_all_returns_all_keys():
    vault = _FakeVault({
        "prod": {"A": _FakeEntry("1"), "B": _FakeEntry("2")},
        "staging": {"A": _FakeEntry("1"), "C": _FakeEntry("3")},
    })
    results = compare_all(vault, ["prod", "staging"], "pass")
    keys = {r.key for r in results}
    assert keys == {"A", "B", "C"}


def test_compare_all_requires_two_envs():
    vault = _FakeVault({})
    with pytest.raises(CompareError):
        compare_all(vault, ["prod"], "pass")


def test_compare_all_statuses():
    vault = _FakeVault({
        "prod": {"MATCH": _FakeEntry("x"), "DIFF": _FakeEntry("a")},
        "staging": {"MATCH": _FakeEntry("x"), "DIFF": _FakeEntry("b")},
    })
    results = {r.key: r for r in compare_all(vault, ["prod", "staging"], "pass")}
    assert results["MATCH"].status == "match"
    assert results["DIFF"].status == "mismatch"
