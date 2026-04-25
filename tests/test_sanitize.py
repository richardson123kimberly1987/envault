"""Tests for envault.sanitize."""

from __future__ import annotations

import pytest
from envault.sanitize import (
    SANITIZE_RULES,
    SanitizeError,
    SanitizeResult,
    sanitize_secret,
    sanitize_all,
)


class _FakeEntry:
    def __init__(self, value: str):
        self._value = value

    def to_dict(self) -> dict:
        return {"value": self._value}


class _FakeVault:
    def __init__(self, data: dict[str, dict[str, str]]):
        # data: {env: {key: value}}
        self._data = {env: dict(vals) for env, vals in data.items()}

    def get_secret(self, key: str, env: str):
        val = self._data.get(env, {}).get(key)
        if val is None:
            return None
        return _FakeEntry(val)

    def set_secret(self, key: str, value: str, env: str):
        self._data.setdefault(env, {})[key] = value

    def list_secrets(self, env: str) -> list[str]:
        return list(self._data.get(env, {}).keys())


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def test_sanitize_rules_constant_not_empty():
    assert len(SANITIZE_RULES) > 0


def test_sanitize_rules_keys_are_strings():
    for k, v in SANITIZE_RULES.items():
        assert isinstance(k, str)
        assert isinstance(v, str)


# ---------------------------------------------------------------------------
# SanitizeResult.to_dict
# ---------------------------------------------------------------------------

def test_sanitize_result_to_dict():
    r = SanitizeResult(
        key="API_KEY",
        environment="prod",
        original="  secret  ",
        sanitized="secret",
        rules_applied=["strip_whitespace"],
        changed=True,
    )
    d = r.to_dict()
    assert d["key"] == "API_KEY"
    assert d["environment"] == "prod"
    assert d["changed"] is True
    assert "strip_whitespace" in d["rules_applied"]


# ---------------------------------------------------------------------------
# sanitize_secret
# ---------------------------------------------------------------------------

def test_sanitize_strips_whitespace():
    vault = _FakeVault({"dev": {"TOKEN": "  abc  "}})
    result = sanitize_secret(vault, "TOKEN", "dev", ["strip_whitespace"])
    assert result.sanitized == "abc"
    assert result.changed is True
    assert "strip_whitespace" in result.rules_applied


def test_sanitize_strips_newlines():
    vault = _FakeVault({"dev": {"TOKEN": "abc\ndef\r"}})
    result = sanitize_secret(vault, "TOKEN", "dev", ["strip_newlines"])
    assert result.sanitized == "abcdef"
    assert result.changed is True


def test_sanitize_strips_null_bytes():
    vault = _FakeVault({"dev": {"TOKEN": "ab\x00cd"}})
    result = sanitize_secret(vault, "TOKEN", "dev", ["strip_null_bytes"])
    assert result.sanitized == "abcd"


def test_sanitize_strips_ansi():
    vault = _FakeVault({"dev": {"MSG": "\x1b[32mgreen\x1b[0m"}})
    result = sanitize_secret(vault, "MSG", "dev", ["strip_ansi"])
    assert result.sanitized == "green"


def test_sanitize_strips_control_chars():
    vault = _FakeVault({"dev": {"VAL": "hello\x07world"}})
    result = sanitize_secret(vault, "VAL", "dev", ["strip_control"])
    assert result.sanitized == "helloworld"


def test_sanitize_no_change_when_already_clean():
    vault = _FakeVault({"dev": {"KEY": "clean_value"}})
    result = sanitize_secret(vault, "KEY", "dev", ["strip_whitespace"])
    assert result.changed is False
    assert result.rules_applied == []


def test_sanitize_missing_secret_raises():
    vault = _FakeVault({"dev": {}})
    with pytest.raises(SanitizeError, match="not found"):
        sanitize_secret(vault, "MISSING", "dev")


def test_sanitize_unknown_rule_raises():
    vault = _FakeVault({"dev": {"KEY": "value"}})
    with pytest.raises(SanitizeError, match="Unknown sanitization rule"):
        sanitize_secret(vault, "KEY", "dev", ["nonexistent_rule"])


def test_sanitize_persists_changed_value():
    vault = _FakeVault({"dev": {"KEY": "  value  "}})
    sanitize_secret(vault, "KEY", "dev", ["strip_whitespace"])
    entry = vault.get_secret("KEY", "dev")
    assert entry.to_dict()["value"] == "value"


def test_sanitize_default_rules_applied_when_none_given():
    vault = _FakeVault({"dev": {"KEY": "  hello\n\x00  "}})
    result = sanitize_secret(vault, "KEY", "dev")
    assert result.sanitized == "hello"
    assert result.changed is True


# ---------------------------------------------------------------------------
# sanitize_all
# ---------------------------------------------------------------------------

def test_sanitize_all_returns_results_for_each_secret():
    vault = _FakeVault({"prod": {"A": "  a  ", "B": "b"}})
    results = sanitize_all(vault, "prod", ["strip_whitespace"])
    assert len(results) == 2
    keys = {r.key for r in results}
    assert keys == {"A", "B"}


def test_sanitize_all_empty_environment_returns_empty_list():
    vault = _FakeVault({"prod": {}})
    results = sanitize_all(vault, "prod")
    assert results == []
