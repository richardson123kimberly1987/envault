"""Tests for envault.crossref."""
from __future__ import annotations

from typing import Dict, List, Optional

import pytest

from envault.crossref import CrossRefError, CrossRefMatch, CrossRefResult, find_crossrefs


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str):
        self._value = value

    def decrypt(self, passphrase: str) -> str:
        if passphrase == "bad":
            raise ValueError("wrong passphrase")
        return self._value

    def to_dict(self):
        return {"value": self._value}


class _FakeVault:
    def __init__(self, data: Dict[str, Dict[str, str]]):
        # data: {env: {key: plaintext}}
        self._data = data

    def list_environments(self) -> List[str]:
        return list(self._data.keys())

    def list_secrets(self, env: str) -> List[str]:
        return list(self._data.get(env, {}).keys())

    def get_secret(self, env: str, key: str) -> Optional[_FakeEntry]:
        envdata = self._data.get(env, {})
        if key not in envdata:
            return None
        return _FakeEntry(envdata[key])


# ---------------------------------------------------------------------------
# Tests: data classes
# ---------------------------------------------------------------------------

def test_cross_ref_match_to_dict():
    m = CrossRefMatch(key="DB_PASS", environments=["prod", "staging"])
    d = m.to_dict()
    assert d["key"] == "DB_PASS"
    assert d["environments"] == ["prod", "staging"]


def test_cross_ref_result_to_dict():
    r = CrossRefResult(matches=[], scanned=5)
    d = r.to_dict()
    assert d["scanned"] == 5
    assert d["matches"] == []


# ---------------------------------------------------------------------------
# Tests: find_crossrefs
# ---------------------------------------------------------------------------

def test_no_matches_when_all_values_unique():
    vault = _FakeVault({"dev": {"A": "val1"}, "prod": {"A": "val2"}})
    result = find_crossrefs(vault)
    assert result.matches == []
    assert result.scanned == 2


def test_detects_shared_value_across_envs():
    vault = _FakeVault({
        "dev": {"SECRET": "shared"},
        "prod": {"SECRET": "shared"},
    })
    result = find_crossrefs(vault)
    assert len(result.matches) == 1
    assert result.matches[0].key == "SECRET"
    assert set(result.matches[0].environments) == {"dev", "prod"}


def test_environment_filter_excludes_unrelated_match():
    vault = _FakeVault({
        "dev": {"K": "same"},
        "staging": {"K": "same"},
        "prod": {"K": "different"},
    })
    result = find_crossrefs(vault, environment="prod")
    # prod does not share value with anyone
    assert result.matches == []


def test_environment_filter_includes_relevant_match():
    vault = _FakeVault({
        "dev": {"K": "same"},
        "staging": {"K": "same"},
    })
    result = find_crossrefs(vault, environment="dev")
    assert len(result.matches) == 1


def test_decrypt_failure_skips_entry():
    vault = _FakeVault({"dev": {"K": "v"}, "prod": {"K": "v"}})
    # passphrase="bad" triggers ValueError inside _FakeEntry.decrypt
    result = find_crossrefs(vault, passphrase="bad")
    assert result.scanned == 0
    assert result.matches == []


def test_results_sorted_by_key():
    vault = _FakeVault({
        "dev": {"Z": "same", "A": "same2"},
        "prod": {"Z": "same", "A": "same2"},
    })
    result = find_crossrefs(vault)
    keys = [m.key for m in result.matches]
    assert keys == sorted(keys)
