"""Tests for envault.entropy."""
from __future__ import annotations

import pytest

from envault.entropy import (
    EntropyError,
    EntropyResult,
    analyze_all_entropy,
    analyze_entropy,
    _shannon_entropy,
    _rate,
)


# ---------------------------------------------------------------------------
# Fake vault helpers
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str):
        self._value = value

    def decrypt(self) -> str:
        return self._value

    def to_dict(self):
        return {"value": self._value}


class _FakeVault:
    def __init__(self, secrets: dict):
        # secrets: {env: {name: value}}
        self._secrets = secrets

    def get_secret(self, name, env):
        return (
            _FakeEntry(self._secrets[env][name])
            if env in self._secrets and name in self._secrets[env]
            else None
        )

    def list_secrets(self, env):
        return list(self._secrets.get(env, {}).keys())


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------

def test_shannon_entropy_empty_string():
    assert _shannon_entropy("") == 0.0


def test_shannon_entropy_single_char():
    assert _shannon_entropy("aaaa") == 0.0


def test_shannon_entropy_two_equal_chars():
    result = _shannon_entropy("ab")
    assert abs(result - 1.0) < 1e-9


def test_rate_very_low():
    assert _rate(0.0) == "very_low"


def test_rate_low():
    assert _rate(2.5) == "low"


def test_rate_medium():
    assert _rate(4.0) == "medium"


def test_rate_high():
    assert _rate(4.8) == "high"


def test_rate_very_high():
    assert _rate(6.0) == "very_high"


def test_analyze_entropy_returns_result():
    vault = _FakeVault({"prod": {"API_KEY": "aAbBcCdD1234!@#$"}})
    result = analyze_entropy(vault, "API_KEY", "prod")
    assert isinstance(result, EntropyResult)
    assert result.secret_name == "API_KEY"
    assert result.environment == "prod"
    assert result.entropy > 0
    assert result.length == len("aAbBcCdD1234!@#$")
    assert result.rating in {"very_low", "low", "medium", "high", "very_high"}


def test_analyze_entropy_missing_secret_raises():
    vault = _FakeVault({"prod": {}})
    with pytest.raises(EntropyError):
        analyze_entropy(vault, "MISSING", "prod")


def test_analyze_entropy_to_dict():
    vault = _FakeVault({"dev": {"TOKEN": "secret123"}})
    result = analyze_entropy(vault, "TOKEN", "dev")
    d = result.to_dict()
    assert d["secret_name"] == "TOKEN"
    assert "entropy" in d
    assert "rating" in d
    assert "unique_chars" in d


def test_analyze_all_entropy_returns_list():
    vault = _FakeVault({"staging": {"A": "hello", "B": "world"}})
    results = analyze_all_entropy(vault, "staging")
    assert len(results) == 2
    names = {r.secret_name for r in results}
    assert names == {"A", "B"}


def test_analyze_all_entropy_empty_environment():
    vault = _FakeVault({"empty": {}})
    results = analyze_all_entropy(vault, "empty")
    assert results == []
