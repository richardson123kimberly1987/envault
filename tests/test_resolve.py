"""Tests for envault.resolve."""

from __future__ import annotations

import pytest

from envault.resolve import ResolveError, ResolveResult, resolve_all, resolve_secret


# ---------------------------------------------------------------------------
# Fake helpers
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str) -> None:
        self._value = value

    def to_dict(self):
        return {"value": self._value}

    def decrypt(self, passphrase: str) -> str:  # noqa: ARG002
        return self._value


class _FakeVault:
    def __init__(self, data: dict[str, dict[str, _FakeEntry]]) -> None:
        # data = {env: {key: entry}}
        self._data = data

    def get_secret(self, env: str, key: str):
        return self._data.get(env, {}).get(key)

    def list_secrets(self, env: str) -> list[str]:
        return list(self._data.get(env, {}).keys())


# ---------------------------------------------------------------------------
# ResolveResult.to_dict
# ---------------------------------------------------------------------------

def test_resolve_result_to_dict():
    r = ResolveResult(key="DB", value="postgres", resolved_env="prod", chain=["prod"], found=True)
    d = r.to_dict()
    assert d["key"] == "DB"
    assert d["value"] == "postgres"
    assert d["resolved_env"] == "prod"
    assert d["found"] is True
    assert d["chain"] == ["prod"]


# ---------------------------------------------------------------------------
# resolve_secret
# ---------------------------------------------------------------------------

def test_resolve_secret_found_in_first_env():
    vault = _FakeVault({"prod": {"API_KEY": _FakeEntry("secret")}})
    result = resolve_secret(vault, "API_KEY", ["prod", "staging"], "pass")
    assert result.found is True
    assert result.value == "secret"
    assert result.resolved_env == "prod"


def test_resolve_secret_falls_back_to_second_env():
    vault = _FakeVault({
        "prod": {},
        "staging": {"API_KEY": _FakeEntry("staging-secret")},
    })
    result = resolve_secret(vault, "API_KEY", ["prod", "staging"], "pass")
    assert result.found is True
    assert result.value == "staging-secret"
    assert result.resolved_env == "staging"


def test_resolve_secret_not_found_in_any_env():
    vault = _FakeVault({"prod": {}, "staging": {}})
    result = resolve_secret(vault, "MISSING", ["prod", "staging"], "pass")
    assert result.found is False
    assert result.value is None
    assert result.resolved_env is None


def test_resolve_secret_empty_chain_raises():
    vault = _FakeVault({})
    with pytest.raises(ResolveError, match="env_chain"):
        resolve_secret(vault, "KEY", [], "pass")


def test_resolve_secret_chain_preserved_in_result():
    vault = _FakeVault({"a": {"X": _FakeEntry("1")}})
    result = resolve_secret(vault, "X", ["a", "b", "c"], "pass")
    assert result.chain == ["a", "b", "c"]


# ---------------------------------------------------------------------------
# resolve_all
# ---------------------------------------------------------------------------

def test_resolve_all_collects_keys_across_envs():
    vault = _FakeVault({
        "prod": {"A": _FakeEntry("a-prod"), "B": _FakeEntry("b-prod")},
        "staging": {"B": _FakeEntry("b-staging"), "C": _FakeEntry("c-staging")},
    })
    results = resolve_all(vault, ["prod", "staging"], "pass")
    keys = {r.key for r in results}
    assert keys == {"A", "B", "C"}


def test_resolve_all_respects_priority_order():
    vault = _FakeVault({
        "prod": {"SHARED": _FakeEntry("prod-value")},
        "staging": {"SHARED": _FakeEntry("staging-value")},
    })
    results = resolve_all(vault, ["prod", "staging"], "pass")
    shared = next(r for r in results if r.key == "SHARED")
    assert shared.value == "prod-value"
    assert shared.resolved_env == "prod"


def test_resolve_all_empty_chain_raises():
    vault = _FakeVault({})
    with pytest.raises(ResolveError):
        resolve_all(vault, [], "pass")


def test_resolve_all_returns_sorted_keys():
    vault = _FakeVault({
        "prod": {"ZEBRA": _FakeEntry("z"), "ALPHA": _FakeEntry("a")},
    })
    results = resolve_all(vault, ["prod"], "pass")
    assert [r.key for r in results] == ["ALPHA", "ZEBRA"]
