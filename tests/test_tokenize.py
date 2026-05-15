"""Tests for envault.tokenize."""
from __future__ import annotations

import pytest

from envault.tokenize import (
    TOKEN_PREFIX,
    TokenizeError,
    TokenizeResult,
    _generate_token,
    tokenize_secret,
    detokenize_secret,
)


class _FakeEntry:
    def __init__(self, value: str):
        self._value = value

    def decrypt(self) -> str:
        return self._value

    def update_value(self, v: str):
        self._value = v

    def to_dict(self):
        return {"value": self._value, "metadata": {}}


class _FakeVault:
    def __init__(self, secrets=None):
        self._secrets: dict = secrets or {}

    def get_secret(self, key, environment):
        return self._secrets.get((key, environment))

    def set_secret(self, key, environment, entry):
        self._secrets[(key, environment)] = entry


# ---------------------------------------------------------------------------
# _generate_token
# ---------------------------------------------------------------------------

def test_generate_token_has_prefix():
    token = _generate_token("MY_KEY", "prod")
    assert token.startswith(TOKEN_PREFIX)


def test_generate_token_deterministic_with_seed():
    seed = b"fixed-seed-1234"
    t1 = _generate_token("KEY", "dev", seed=seed)
    t2 = _generate_token("KEY", "dev", seed=seed)
    assert t1 == t2


def test_generate_token_unique_without_seed():
    t1 = _generate_token("KEY", "dev")
    t2 = _generate_token("KEY", "dev")
    assert t1 != t2


# ---------------------------------------------------------------------------
# tokenize_secret
# ---------------------------------------------------------------------------

def test_tokenize_replaces_value():
    entry = _FakeEntry("super-secret")
    vault = _FakeVault({("API_KEY", "prod"): entry})
    result = tokenize_secret(vault, "API_KEY", "prod", seed=b"abc")
    assert result.token.startswith(TOKEN_PREFIX)
    assert result.replaced is True
    assert entry._value == result.token


def test_tokenize_returns_tokenize_result():
    entry = _FakeEntry("value")
    vault = _FakeVault({("DB_PASS", "staging"): entry})
    result = tokenize_secret(vault, "DB_PASS", "staging", seed=b"xyz")
    assert isinstance(result, TokenizeResult)
    assert result.key == "DB_PASS"
    assert result.environment == "staging"


def test_tokenize_missing_secret_raises():
    vault = _FakeVault()
    with pytest.raises(TokenizeError, match="not found"):
        tokenize_secret(vault, "MISSING", "prod")


def test_tokenize_result_to_dict():
    entry = _FakeEntry("val")
    vault = _FakeVault({("K", "e"): entry})
    result = tokenize_secret(vault, "K", "e", seed=b"s")
    d = result.to_dict()
    assert d["key"] == "K"
    assert d["environment"] == "e"
    assert d["replaced"] is True
    assert "token" in d


# ---------------------------------------------------------------------------
# detokenize_secret
# ---------------------------------------------------------------------------

def test_detokenize_restores_value():
    token_value = TOKEN_PREFIX + "a" * 32
    entry = _FakeEntry(token_value)
    vault = _FakeVault({("API_KEY", "prod"): entry})
    result = detokenize_secret(vault, "API_KEY", "prod", "original-secret")
    assert result.replaced is True
    assert entry._value == "original-secret"
    assert result.token == token_value


def test_detokenize_non_tokenized_raises():
    entry = _FakeEntry("plaintext-value")
    vault = _FakeVault({("KEY", "dev"): entry})
    with pytest.raises(TokenizeError, match="does not appear to be tokenized"):
        detokenize_secret(vault, "KEY", "dev", "something")


def test_detokenize_missing_secret_raises():
    vault = _FakeVault()
    with pytest.raises(TokenizeError, match="not found"):
        detokenize_secret(vault, "GHOST", "prod", "val")
