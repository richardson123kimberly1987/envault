"""Tests for envault.trim."""
from __future__ import annotations

import pytest

from envault.trim import (
    TRIM_MODES,
    TrimError,
    TrimResult,
    trim_all,
    trim_secret,
)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str):
        self._value = value
        self._updated: str | None = None

    def decrypt(self, passphrase: str) -> str:
        return self._value

    def update_value(self, new_value: str, passphrase: str) -> None:
        self._value = new_value
        self._updated = new_value

    def to_dict(self) -> dict:
        return {"value": self._value}


class _FakeVault:
    def __init__(self, secrets: dict[str, dict[str, _FakeEntry]]):
        # secrets[env][name] -> entry
        self._secrets = secrets
        self.saved = False

    def get_secret(self, name: str, env: str):
        return self._secrets.get(env, {}).get(name)

    def list_secrets(self, env: str):
        return list(self._secrets.get(env, {}).keys())

    def save(self):
        self.saved = True


# ---------------------------------------------------------------------------
# TrimResult.to_dict
# ---------------------------------------------------------------------------

def test_trim_result_to_dict():
    r = TrimResult("KEY", "prod", "  v  ", "v", True, "full")
    d = r.to_dict()
    assert d["secret"] == "KEY"
    assert d["environment"] == "prod"
    assert d["original"] == "  v  "
    assert d["trimmed"] == "v"
    assert d["changed"] is True
    assert d["mode"] == "full"


# ---------------------------------------------------------------------------
# TRIM_MODES constant
# ---------------------------------------------------------------------------

def test_trim_modes_not_empty():
    assert len(TRIM_MODES) > 0


# ---------------------------------------------------------------------------
# trim_secret
# ---------------------------------------------------------------------------

def test_trim_secret_full_strips_both_sides():
    entry = _FakeEntry("  hello  ")
    vault = _FakeVault({"dev": {"API_KEY": entry}})
    result = trim_secret(vault, "API_KEY", "dev", "pass")
    assert result.trimmed == "hello"
    assert result.changed is True
    assert vault.saved is True


def test_trim_secret_leading_only():
    entry = _FakeEntry("  hello  ")
    vault = _FakeVault({"dev": {"API_KEY": entry}})
    result = trim_secret(vault, "API_KEY", "dev", "pass", mode="leading")
    assert result.trimmed == "hello  "


def test_trim_secret_trailing_only():
    entry = _FakeEntry("  hello  ")
    vault = _FakeVault({"dev": {"API_KEY": entry}})
    result = trim_secret(vault, "API_KEY", "dev", "pass", mode="trailing")
    assert result.trimmed == "  hello"


def test_trim_secret_lines_mode():
    entry = _FakeEntry("  line1  \n  line2  ")
    vault = _FakeVault({"dev": {"KEY": entry}})
    result = trim_secret(vault, "KEY", "dev", "pass", mode="lines")
    assert result.trimmed == "line1\nline2"


def test_trim_secret_no_change_does_not_save():
    entry = _FakeEntry("clean")
    vault = _FakeVault({"dev": {"KEY": entry}})
    result = trim_secret(vault, "KEY", "dev", "pass")
    assert result.changed is False
    assert vault.saved is False


def test_trim_secret_dry_run_does_not_save():
    entry = _FakeEntry("  dirty  ")
    vault = _FakeVault({"dev": {"KEY": entry}})
    result = trim_secret(vault, "KEY", "dev", "pass", dry_run=True)
    assert result.changed is True
    assert vault.saved is False


def test_trim_secret_missing_raises():
    vault = _FakeVault({})
    with pytest.raises(TrimError, match="not found"):
        trim_secret(vault, "MISSING", "dev", "pass")


def test_trim_secret_invalid_mode_raises():
    entry = _FakeEntry("value")
    vault = _FakeVault({"dev": {"KEY": entry}})
    with pytest.raises(TrimError, match="Unknown trim mode"):
        trim_secret(vault, "KEY", "dev", "pass", mode="bogus")


# ---------------------------------------------------------------------------
# trim_all
# ---------------------------------------------------------------------------

def test_trim_all_returns_results_for_each_secret():
    vault = _FakeVault({
        "prod": {
            "A": _FakeEntry(" a "),
            "B": _FakeEntry("b"),
        }
    })
    results = trim_all(vault, "prod", "pass")
    assert len(results) == 2
    names = {r.secret for r in results}
    assert names == {"A", "B"}


def test_trim_all_empty_environment_returns_empty_list():
    vault = _FakeVault({"prod": {}})
    results = trim_all(vault, "prod", "pass")
    assert results == []
