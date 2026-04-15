"""Tests for envault.search."""

from __future__ import annotations

import pytest

from envault.search import SearchError, SearchResult, search_secrets


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, version=1, created_at="2024-01-01", updated_at="2024-06-01"):
        self._d = {"version": version, "created_at": created_at, "updated_at": updated_at}

    def to_dict(self):
        return self._d


class _FakeVault:
    def __init__(self):
        self._data = {
            "production": {
                "DB_PASSWORD": _FakeEntry(version=3),
                "API_KEY": _FakeEntry(version=1),
                "SECRET_TOKEN": _FakeEntry(version=2),
            },
            "staging": {
                "DB_PASSWORD": _FakeEntry(version=1),
                "DEBUG_FLAG": _FakeEntry(version=1),
            },
        }

    def list_environments(self):
        return list(self._data.keys())

    def list_secrets(self, env):
        return list(self._data.get(env, {}).keys())

    def get(self, env, key):
        return self._data.get(env, {}).get(key)


@pytest.fixture
def vault():
    return _FakeVault()


# ---------------------------------------------------------------------------
# SearchResult
# ---------------------------------------------------------------------------

def test_search_result_to_dict():
    r = SearchResult(environment="prod", key="FOO", version=2,
                     created_at="2024-01-01", updated_at="2024-06-01")
    d = r.to_dict()
    assert d["environment"] == "prod"
    assert d["key"] == "FOO"
    assert d["version"] == 2


# ---------------------------------------------------------------------------
# search_secrets — glob
# ---------------------------------------------------------------------------

def test_glob_matches_prefix(vault):
    results = search_secrets(vault, "DB_*")
    keys = [(r.environment, r.key) for r in results]
    assert ("production", "DB_PASSWORD") in keys
    assert ("staging", "DB_PASSWORD") in keys


def test_glob_no_match_returns_empty(vault):
    assert search_secrets(vault, "NONEXISTENT_*") == []


def test_glob_exact_match(vault):
    results = search_secrets(vault, "API_KEY")
    assert len(results) == 1
    assert results[0].key == "API_KEY"


def test_results_sorted(vault):
    results = search_secrets(vault, "*")
    pairs = [(r.environment, r.key) for r in results]
    assert pairs == sorted(pairs)


# ---------------------------------------------------------------------------
# search_secrets — environment filter
# ---------------------------------------------------------------------------

def test_filter_by_environment(vault):
    results = search_secrets(vault, "DB_*", environment="staging")
    assert all(r.environment == "staging" for r in results)
    assert len(results) == 1


# ---------------------------------------------------------------------------
# search_secrets — regex
# ---------------------------------------------------------------------------

def test_regex_match(vault):
    results = search_secrets(vault, r"^(API|SECRET)_", use_regex=True)
    keys = {r.key for r in results}
    assert "API_KEY" in keys
    assert "SECRET_TOKEN" in keys
    assert "DB_PASSWORD" not in keys


def test_invalid_regex_raises(vault):
    with pytest.raises(SearchError, match="Invalid regex"):
        search_secrets(vault, r"[invalid", use_regex=True)
