"""Tests for envault.normalize."""

from __future__ import annotations

import pytest

from envault.normalize import (
    NormalizeError,
    NormalizeResult,
    normalize_all,
    normalize_secret,
    _apply_normalize,
)


# ---------------------------------------------------------------------------
# Fake helpers
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str, passphrase: str = "pass"):
        self._value = value
        self._passphrase = passphrase

    def decrypt(self, passphrase: str) -> str:
        return self._value

    def update_value(self, new_value: str, passphrase: str) -> None:
        self._value = new_value

    def to_dict(self) -> dict:
        return {"value": self._value}


class _FakeVault:
    def __init__(self, secrets: dict[str, dict[str, _FakeEntry]]):
        # secrets[env][key] = entry
        self._secrets = secrets
        self.saved = False

    def get_secret(self, key: str, environment: str):
        return self._secrets.get(environment, {}).get(key)

    def list_secrets(self, environment: str) -> list[str]:
        return list(self._secrets.get(environment, {}).keys())

    def save(self) -> None:
        self.saved = True


# ---------------------------------------------------------------------------
# _apply_normalize
# ---------------------------------------------------------------------------

def test_apply_normalize_strips_whitespace():
    assert _apply_normalize("  hello  ") == "hello"


def test_apply_normalize_normalizes_crlf():
    assert _apply_normalize("foo\r\nbar") == "foo\nbar"


def test_apply_normalize_normalizes_cr():
    assert _apply_normalize("foo\rbar") == "foo\nbar"


def test_apply_normalize_unchanged_clean_value():
    assert _apply_normalize("clean") == "clean"


# ---------------------------------------------------------------------------
# normalize_secret
# ---------------------------------------------------------------------------

def test_normalize_secret_changed():
    entry = _FakeEntry("  secret  ")
    vault = _FakeVault({"prod": {"API_KEY": entry}})
    result = normalize_secret(vault, "API_KEY", "prod", "pass")

    assert isinstance(result, NormalizeResult)
    assert result.changed is True
    assert result.normalized == "secret"
    assert result.original == "  secret  "
    assert vault.saved is True


def test_normalize_secret_unchanged():
    entry = _FakeEntry("clean")
    vault = _FakeVault({"prod": {"API_KEY": entry}})
    result = normalize_secret(vault, "API_KEY", "prod", "pass")

    assert result.changed is False
    assert vault.saved is False


def test_normalize_secret_missing_raises():
    vault = _FakeVault({"prod": {}})
    with pytest.raises(NormalizeError, match="API_KEY"):
        normalize_secret(vault, "API_KEY", "prod", "pass")


def test_normalize_secret_to_dict():
    entry = _FakeEntry("  val  ")
    vault = _FakeVault({"prod": {"K": entry}})
    result = normalize_secret(vault, "K", "prod", "pass")
    d = result.to_dict()
    assert d["key"] == "K"
    assert d["changed"] is True


# ---------------------------------------------------------------------------
# normalize_all
# ---------------------------------------------------------------------------

def test_normalize_all_returns_all_results():
    vault = _FakeVault({
        "dev": {
            "A": _FakeEntry(" a "),
            "B": _FakeEntry("b"),
        }
    })
    results = normalize_all(vault, "dev", "pass")
    assert len(results) == 2
    keys = {r.key for r in results}
    assert keys == {"A", "B"}


def test_normalize_all_empty_environment():
    vault = _FakeVault({"staging": {}})
    results = normalize_all(vault, "staging", "pass")
    assert results == []
