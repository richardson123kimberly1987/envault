"""Tests for envault.summarize."""
from __future__ import annotations

import pytest

from envault.summarize import SummarizeError, SummaryResult, summarize_all, summarize_environment


class _FakeEntry:
    def __init__(self, expires_at=None, locked=False, tags=None):
        self._data = {
            "expires_at": expires_at,
            "locked": locked,
            "tags": tags or [],
        }

    def to_dict(self):
        return dict(self._data)


class _FakeVault:
    def __init__(self, envs):
        # envs: dict[str, dict[str, _FakeEntry]]
        self._envs = envs

    def list_environments(self):
        return list(self._envs.keys())

    def list_secrets(self, env):
        return list(self._envs.get(env, {}).keys())

    def get_secret(self, env, name):
        return self._envs.get(env, {}).get(name)


# ---------------------------------------------------------------------------

def test_summary_result_to_dict():
    r = SummaryResult(environment="prod", total=3, has_expiry=1, locked=1, tagged=2, secret_names=["A"])
    d = r.to_dict()
    assert d["environment"] == "prod"
    assert d["total"] == 3
    assert d["has_expiry"] == 1
    assert d["locked"] == 1
    assert d["tagged"] == 2
    assert d["secret_names"] == ["A"]


def test_summarize_environment_counts():
    vault = _FakeVault({
        "staging": {
            "DB_PASS": _FakeEntry(expires_at="2030-01-01", locked=False, tags=["db"]),
            "API_KEY": _FakeEntry(expires_at=None, locked=True, tags=[]),
            "SECRET": _FakeEntry(expires_at=None, locked=False, tags=[]),
        }
    })
    result = summarize_environment(vault, "staging")
    assert result.total == 3
    assert result.has_expiry == 1
    assert result.locked == 1
    assert result.tagged == 1
    assert set(result.secret_names) == {"DB_PASS", "API_KEY", "SECRET"}


def test_summarize_environment_empty():
    vault = _FakeVault({"dev": {}})
    result = summarize_environment(vault, "dev")
    assert result.total == 0
    assert result.has_expiry == 0
    assert result.locked == 0
    assert result.tagged == 0


def test_summarize_environment_missing_raises():
    vault = _FakeVault({"dev": {}})
    with pytest.raises(SummarizeError, match="not found"):
        summarize_environment(vault, "prod")


def test_summarize_all_returns_one_per_env():
    vault = _FakeVault({
        "dev": {"A": _FakeEntry()},
        "prod": {"A": _FakeEntry(), "B": _FakeEntry()},
    })
    results = summarize_all(vault)
    assert len(results) == 2
    totals = {r.environment: r.total for r in results}
    assert totals["dev"] == 1
    assert totals["prod"] == 2


def test_summarize_all_empty_vault():
    vault = _FakeVault({})
    assert summarize_all(vault) == []
