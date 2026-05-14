"""Tests for envault.obfuscate."""
from __future__ import annotations

import pytest

from envault.obfuscate import (
    OBFUSCATE_STYLES,
    ObfuscateError,
    ObfuscateResult,
    obfuscate_all,
    obfuscate_secret,
)


class _FakeEntry:
    def __init__(self, value: str) -> None:
        self._value = value

    def decrypt(self, passphrase: str = "") -> str:
        if passphrase == "wrong":
            raise ValueError("bad passphrase")
        return self._value

    def to_dict(self) -> dict:
        return {"value": self._value}


class _FakeVault:
    def __init__(self, secrets: dict[str, dict[str, _FakeEntry]]) -> None:
        self._secrets = secrets

    def get_secret(self, environment: str, key: str):
        return self._secrets.get(environment, {}).get(key)

    def list_secrets(self, environment: str):
        return list(self._secrets.get(environment, {}).keys())


# ---------------------------------------------------------------------------
# ObfuscateResult.to_dict
# ---------------------------------------------------------------------------

def test_obfuscate_result_to_dict():
    r = ObfuscateResult(key="K", environment="prod", original_length=5, obfuscated="K****", style="partial")
    d = r.to_dict()
    assert d["key"] == "K"
    assert d["environment"] == "prod"
    assert d["original_length"] == 5
    assert d["obfuscated"] == "K****"
    assert d["style"] == "partial"


# ---------------------------------------------------------------------------
# obfuscate_secret – styles
# ---------------------------------------------------------------------------

@pytest.fixture
def vault():
    return _FakeVault({"prod": {"API_KEY": _FakeEntry("abcdefgh")}})


def test_obfuscate_styles_constant_not_empty():
    assert len(OBFUSCATE_STYLES) > 0


def test_obfuscate_partial_style(vault):
    r = obfuscate_secret(vault, "prod", "API_KEY", style="partial")
    assert r.original_length == 8
    assert r.obfuscated.startswith("ab")
    assert "*" in r.obfuscated


def test_obfuscate_full_style(vault):
    r = obfuscate_secret(vault, "prod", "API_KEY", style="full")
    assert r.obfuscated == "*" * 8


def test_obfuscate_asterisk_style(vault):
    r = obfuscate_secret(vault, "prod", "API_KEY", style="asterisk")
    assert set(r.obfuscated) == {"*"}
    assert len(r.obfuscated) <= 8


def test_obfuscate_hash_style(vault):
    r = obfuscate_secret(vault, "prod", "API_KEY", style="hash")
    assert set(r.obfuscated) == {"#"}


def test_obfuscate_short_value_full_mask():
    v = _FakeVault({"dev": {"X": _FakeEntry("ab")}})
    r = obfuscate_secret(v, "dev", "X", style="partial")
    assert r.obfuscated == "**"


# ---------------------------------------------------------------------------
# error cases
# ---------------------------------------------------------------------------

def test_obfuscate_missing_secret_raises(vault):
    with pytest.raises(ObfuscateError, match="not found"):
        obfuscate_secret(vault, "prod", "MISSING", style="full")


def test_obfuscate_unknown_style_raises(vault):
    with pytest.raises(ObfuscateError, match="Unknown style"):
        obfuscate_secret(vault, "prod", "API_KEY", style="invisible")


def test_obfuscate_wrong_passphrase_raises(vault):
    with pytest.raises(ObfuscateError, match="Failed to decrypt"):
        obfuscate_secret(vault, "prod", "API_KEY", style="full", passphrase="wrong")


# ---------------------------------------------------------------------------
# obfuscate_all
# ---------------------------------------------------------------------------

def test_obfuscate_all_returns_all_keys():
    v = _FakeVault({"staging": {
        "DB_PASS": _FakeEntry("secret1"),
        "API_KEY": _FakeEntry("secret2"),
    }})
    results = obfuscate_all(v, "staging", style="full")
    assert len(results) == 2
    keys = {r.key for r in results}
    assert keys == {"DB_PASS", "API_KEY"}


def test_obfuscate_all_empty_environment():
    v = _FakeVault({})
    results = obfuscate_all(v, "empty", style="partial")
    assert results == []
