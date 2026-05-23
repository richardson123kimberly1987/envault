"""Tests for envault.spotlight."""
from __future__ import annotations

import pytest
from envault.spotlight import (
    SpotlightError,
    SpotlightMatch,
    SpotlightResult,
    spotlight_secrets,
    _safe_preview,
)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str):
        self._value = value

    def decrypt(self) -> str:
        return self._value

    def to_dict(self):
        return {"value": self._value}


class _FakeVault:
    def __init__(self, data: dict):
        # data = {env: {key: value}}
        self._data = data

    def list_environments(self):
        return list(self._data.keys())

    def list_secrets(self, env: str):
        return list(self._data.get(env, {}).keys())

    def get_secret(self, env: str, key: str):
        val = self._data.get(env, {}).get(key)
        return _FakeEntry(val) if val is not None else None


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------

def test_spotlight_result_to_dict():
    r = SpotlightResult(pattern="foo", matches=[], total=0)
    d = r.to_dict()
    assert d["pattern"] == "foo"
    assert d["matches"] == []
    assert d["total"] == 0


def test_spotlight_match_to_dict():
    m = SpotlightMatch(environment="prod", key="DB_PASS", preview="***pass***")
    d = m.to_dict()
    assert d["environment"] == "prod"
    assert d["key"] == "DB_PASS"
    assert d["preview"] == "***pass***"


def test_safe_preview_contains_matched_text():
    preview = _safe_preview("supersecret123", "secret")
    assert "secret" in preview


def test_safe_preview_invalid_pattern():
    preview = _safe_preview("value", "[invalid")
    assert "invalid pattern" in preview


def test_safe_preview_no_match():
    preview = _safe_preview("hello", "xyz")
    assert "no match" in preview


def test_spotlight_finds_matching_values():
    vault = _FakeVault({"prod": {"DB_PASS": "s3cr3t", "API_KEY": "open"}})
    result = spotlight_secrets(vault, "s3cr3t")
    assert result.total == 1
    assert result.matches[0].key == "DB_PASS"


def test_spotlight_case_insensitive():
    vault = _FakeVault({"prod": {"TOKEN": "MySecretValue"}})
    result = spotlight_secrets(vault, "mysecret")
    assert result.total == 1


def test_spotlight_no_matches():
    vault = _FakeVault({"prod": {"KEY": "nothing_here"}})
    result = spotlight_secrets(vault, "xyz123")
    assert result.total == 0
    assert result.matches == []


def test_spotlight_filters_by_environment():
    vault = _FakeVault({
        "prod": {"KEY": "password123"},
        "dev": {"KEY": "password123"},
    })
    result = spotlight_secrets(vault, "password", environment="prod")
    assert result.total == 1
    assert result.matches[0].environment == "prod"


def test_spotlight_invalid_pattern_raises():
    vault = _FakeVault({"prod": {"KEY": "value"}})
    with pytest.raises(SpotlightError, match="Invalid pattern"):
        spotlight_secrets(vault, "[bad")


def test_spotlight_skips_decrypt_errors():
    class _BadEntry:
        def decrypt(self):
            raise RuntimeError("cannot decrypt")
        def to_dict(self):
            return {}

    class _BrokenVault:
        def list_environments(self):
            return ["prod"]
        def list_secrets(self, env):
            return ["SECRET"]
        def get_secret(self, env, key):
            return _BadEntry()

    result = spotlight_secrets(_BrokenVault(), "anything")
    assert result.total == 0
