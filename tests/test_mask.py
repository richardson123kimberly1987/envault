"""Tests for envault.mask."""
from __future__ import annotations

import pytest

from envault.mask import (
    MaskError,
    MaskResult,
    mask_all,
    mask_full,
    mask_partial,
    mask_secret,
    MASK_CHAR,
    DEFAULT_VISIBLE_CHARS,
)


# ---------------------------------------------------------------------------
# Fake vault helpers
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str):
        self._value = value

    def to_dict(self):
        return {"value": self._value}


class _FakeVault:
    def __init__(self, secrets: dict[str, dict[str, str]]):
        # secrets = {env: {key: value}}
        self._secrets = secrets

    def get_secret(self, environment: str, key: str):
        env = self._secrets.get(environment, {})
        if key not in env:
            return None
        return _FakeEntry(env[key])

    def list_secrets(self, environment: str):
        return list(self._secrets.get(environment, {}).keys())


# ---------------------------------------------------------------------------
# Unit tests for low-level helpers
# ---------------------------------------------------------------------------

def test_mask_full_replaces_all_chars():
    result = mask_full("mysecret")
    assert all(c == MASK_CHAR for c in result)
    assert len(result) == len("mysecret")


def test_mask_full_minimum_length():
    result = mask_full("hi")
    assert len(result) >= 8


def test_mask_partial_shows_last_chars():
    result = mask_partial("supersecretvalue", visible=4)
    assert result.endswith("alue")
    assert MASK_CHAR in result


def test_mask_partial_falls_back_to_full_for_short_values():
    short = "abc"
    result = mask_partial(short, visible=4)
    assert all(c == MASK_CHAR for c in result)


# ---------------------------------------------------------------------------
# mask_secret
# ---------------------------------------------------------------------------

def test_mask_secret_full_strategy():
    vault = _FakeVault({"prod": {"DB_PASS": "hunter2"}})
    res = mask_secret(vault, "prod", "DB_PASS", strategy="full")
    assert isinstance(res, MaskResult)
    assert all(c == MASK_CHAR for c in res.masked_value)
    assert res.strategy == "full"
    assert res.original_length == len("hunter2")


def test_mask_secret_partial_strategy():
    vault = _FakeVault({"prod": {"API_KEY": "abcdefghijklmn"}})
    res = mask_secret(vault, "prod", "API_KEY", strategy="partial", visible=4)
    assert res.masked_value.endswith("lmn".rjust(4, "n")[-4:])
    assert res.strategy == "partial"


def test_mask_secret_missing_key_raises():
    vault = _FakeVault({"prod": {}})
    with pytest.raises(MaskError, match="not found"):
        mask_secret(vault, "prod", "MISSING", strategy="full")


def test_mask_secret_unknown_strategy_raises():
    vault = _FakeVault({"prod": {"KEY": "value"}})
    with pytest.raises(MaskError, match="Unknown masking strategy"):
        mask_secret(vault, "prod", "KEY", strategy="redact")


def test_mask_secret_to_dict_keys():
    vault = _FakeVault({"staging": {"TOKEN": "tok_abc123xyz"}})
    res = mask_secret(vault, "staging", "TOKEN")
    d = res.to_dict()
    assert set(d.keys()) == {"key", "environment", "original_length", "masked_value", "strategy"}


# ---------------------------------------------------------------------------
# mask_all
# ---------------------------------------------------------------------------

def test_mask_all_returns_result_per_secret():
    vault = _FakeVault({"dev": {"A": "secret1", "B": "secret2"}})
    results = mask_all(vault, "dev")
    assert len(results) == 2
    assert all(isinstance(r, MaskResult) for r in results)


def test_mask_all_empty_environment():
    vault = _FakeVault({"dev": {}})
    results = mask_all(vault, "dev")
    assert results == []


def test_mask_all_unknown_environment_returns_empty():
    vault = _FakeVault({})
    results = mask_all(vault, "ghost")
    assert results == []
