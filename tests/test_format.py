"""Tests for envault.format module."""
from __future__ import annotations

import pytest

from envault.format import (
    FORMAT_RULES,
    FormatError,
    FormatResult,
    _apply_format,
    format_all,
    format_secret,
)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str) -> None:
        self._value = value

    def decrypt(self) -> str:
        return self._value

    def update_value(self, v: str) -> None:
        self._value = v

    def to_dict(self):
        return {"value": self._value}


class _FakeVault:
    def __init__(self, secrets: dict[str, str]) -> None:
        self._entries = {k: _FakeEntry(v) for k, v in secrets.items()}
        self.saved = False

    def get_secret(self, env: str, name: str):
        return self._entries.get(name)

    def list_secrets(self, env: str):
        return list(self._entries.keys())

    def save(self) -> None:
        self.saved = True


# ---------------------------------------------------------------------------
# Tests: constants
# ---------------------------------------------------------------------------

def test_format_rules_constant_not_empty():
    assert len(FORMAT_RULES) > 0


# ---------------------------------------------------------------------------
# Tests: _apply_format
# ---------------------------------------------------------------------------

def test_apply_uppercase():
    result, applied = _apply_format("hello", ["uppercase"])
    assert result == "HELLO"
    assert "uppercase" in applied


def test_apply_lowercase():
    result, applied = _apply_format("WORLD", ["lowercase"])
    assert result == "world"


def test_apply_strip():
    result, applied = _apply_format("  hi  ", ["strip"])
    assert result == "hi"


def test_apply_capitalize():
    result, applied = _apply_format("hello world", ["capitalize"])
    assert result == "Hello world"


def test_apply_truncate_default():
    long_val = "x" * 100
    result, applied = _apply_format(long_val, ["truncate"])
    assert len(result) == 64
    assert "truncate" in applied


def test_apply_truncate_custom_len():
    result, _ = _apply_format("abcdef", ["truncate"], truncate_len=3)
    assert result == "abc"


def test_apply_multiple_rules_in_order():
    result, applied = _apply_format("  hello  ", ["strip", "uppercase"])
    assert result == "HELLO"
    assert applied == ["strip", "uppercase"]


def test_apply_unknown_rule_raises():
    with pytest.raises(FormatError, match="Unknown format rule"):
        _apply_format("value", ["unknown_rule"])


# ---------------------------------------------------------------------------
# Tests: format_secret
# ---------------------------------------------------------------------------

def test_format_secret_returns_result():
    vault = _FakeVault({"API_KEY": "  secret  "})
    result = format_secret(vault, "prod", "API_KEY", ["strip"])
    assert isinstance(result, FormatResult)
    assert result.formatted == "secret"
    assert result.original == "  secret  "
    assert result.rules_applied == ["strip"]


def test_format_secret_persists_value():
    vault = _FakeVault({"KEY": "hello"})
    format_secret(vault, "dev", "KEY", ["uppercase"])
    assert vault._entries["KEY"].decrypt() == "HELLO"
    assert vault.saved


def test_format_secret_missing_raises():
    vault = _FakeVault({})
    with pytest.raises(FormatError, match="not found"):
        format_secret(vault, "dev", "MISSING", ["strip"])


def test_format_secret_no_rules_raises():
    vault = _FakeVault({"K": "v"})
    with pytest.raises(FormatError, match="At least one"):
        format_secret(vault, "dev", "K", [])


def test_format_secret_to_dict():
    vault = _FakeVault({"TOKEN": "abc"})
    result = format_secret(vault, "staging", "TOKEN", ["uppercase"])
    d = result.to_dict()
    assert d["secret"] == "TOKEN"
    assert d["environment"] == "staging"
    assert d["formatted"] == "ABC"


# ---------------------------------------------------------------------------
# Tests: format_all
# ---------------------------------------------------------------------------

def test_format_all_applies_to_all_secrets():
    vault = _FakeVault({"A": "hello", "B": "world"})
    results = format_all(vault, "prod", ["uppercase"])
    assert len(results) == 2
    values = {r.secret: r.formatted for r in results}
    assert values["A"] == "HELLO"
    assert values["B"] == "WORLD"


def test_format_all_empty_environment_returns_empty():
    vault = _FakeVault({})
    results = format_all(vault, "prod", ["strip"])
    assert results == []
