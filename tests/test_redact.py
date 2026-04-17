"""Tests for envault.redact."""

from __future__ import annotations

import pytest
from envault.redact import (
    REDACT_PLACEHOLDER,
    RedactError,
    RedactResult,
    redact_full,
    redact_partial,
    redact_secret,
    redact_all,
)


class _FakeEntry:
    def __init__(self, value: str):
        self._value = value

    def to_dict(self):
        return {"value": self._value}


class _FakeVault:
    def __init__(self, data: dict):
        self._data = data

    def list_secrets(self, env: str):
        return list(self._data.get(env, {}).keys())

    def get_secret(self, env: str, key: str):
        return self._data.get(env, {}).get(key)


def test_redact_full_returns_placeholder():
    assert redact_full("supersecret") == REDACT_PLACEHOLDER


def test_redact_full_empty_string():
    assert redact_full("") == REDACT_PLACEHOLDER


def test_redact_partial_masks_prefix():
    result = redact_partial("abcdefgh", visible_chars=4)
    assert result.endswith("efgh")
    assert result.startswith("*")


def test_redact_partial_short_value_returns_placeholder():
    assert redact_partial("abc", visible_chars=4) == REDACT_PLACEHOLDER


def test_redact_partial_empty_returns_placeholder():
    assert redact_partial("") == REDACT_PLACEHOLDER


def test_redact_secret_full():
    r = redact_secret("API_KEY", "mysecretvalue")
    assert isinstance(r, RedactResult)
    assert r.key == "API_KEY"
    assert r.original_length == len("mysecretvalue")
    assert r.redacted_value == REDACT_PLACEHOLDER


def test_redact_secret_partial():
    r = redact_secret("TOKEN", "abcdefgh", partial=True)
    assert r.redacted_value.endswith("efgh")


def test_redact_secret_non_string_raises():
    with pytest.raises(RedactError):
        redact_secret("KEY", 12345)  # type: ignore


def test_redact_result_to_dict():
    r = RedactResult(key="X", original_length=5, redacted_value="***")
    d = r.to_dict()
    assert d["key"] == "X"
    assert d["original_length"] == 5
    assert d["redacted_value"] == "***"


def test_redact_all_returns_results():
    vault = _FakeVault({"prod": {"DB_PASS": _FakeEntry("hunter2"), "API": _FakeEntry("xyz")}})
    results = redact_all(vault, "prod")
    assert len(results) == 2
    assert all(r.redacted_value == REDACT_PLACEHOLDER for r in results)


def test_redact_all_empty_environment():
    vault = _FakeVault({"prod": {}})
    assert redact_all(vault, "prod") == []


def test_redact_all_partial_mode():
    vault = _FakeVault({"dev": {"SECRET": _FakeEntry("abcdefghij")}})
    results = redact_all(vault, "dev", partial=True)
    assert len(results) == 1
    assert results[0].redacted_value != REDACT_PLACEHOLDER
    assert results[0].redacted_value.endswith("ghij")
