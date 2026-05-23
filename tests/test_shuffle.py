"""Tests for envault.shuffle."""

from __future__ import annotations

import pytest

from envault.shuffle import (
    SHUFFLE_CHARSETS,
    ShuffleError,
    ShuffleResult,
    shuffle_secret,
)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str) -> None:
        self._value = value
        self._updated: list[str] = []

    def decrypt(self) -> str:
        return self._value

    def update_value(self, v: str) -> None:
        self._value = v
        self._updated.append(v)

    def to_dict(self) -> dict:
        return {"value": self._value}


class _FakeVault:
    def __init__(self, entries: dict) -> None:
        # entries: {(env, key): _FakeEntry}
        self._entries = entries
        self.saved = False

    def get_secret(self, env: str, key: str):
        return self._entries.get((env, key))

    def save(self) -> None:
        self.saved = True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _vault_with(env: str, key: str, value: str):
    entry = _FakeEntry(value)
    vault = _FakeVault({(env, key): entry})
    return vault, entry


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_shuffle_charsets_not_empty():
    assert SHUFFLE_CHARSETS


def test_shuffle_result_to_dict():
    r = ShuffleResult(
        key="K", environment="prod",
        old_value="old", new_value="new",
        charset="hex", length=8,
    )
    d = r.to_dict()
    assert d["key"] == "K"
    assert d["old_value"] == "old"
    assert d["new_value"] == "new"
    assert d["charset"] == "hex"
    assert d["length"] == 8


def test_shuffle_returns_result_with_correct_length():
    vault, _ = _vault_with("dev", "TOKEN", "original")
    result = shuffle_secret(vault, "dev", "TOKEN", charset="alphanumeric", length=16)
    assert isinstance(result, ShuffleResult)
    assert len(result.new_value) == 16
    assert result.old_value == "original"


def test_shuffle_saves_vault():
    vault, _ = _vault_with("dev", "TOKEN", "original")
    shuffle_secret(vault, "dev", "TOKEN")
    assert vault.saved


def test_shuffle_updates_entry():
    vault, entry = _vault_with("dev", "TOKEN", "original")
    result = shuffle_secret(vault, "dev", "TOKEN", length=10)
    assert entry.decrypt() == result.new_value


def test_shuffle_deterministic_with_seed():
    vault1, _ = _vault_with("dev", "K", "v")
    vault2, _ = _vault_with("dev", "K", "v")
    r1 = shuffle_secret(vault1, "dev", "K", seed=42, length=20)
    r2 = shuffle_secret(vault2, "dev", "K", seed=42, length=20)
    assert r1.new_value == r2.new_value


def test_shuffle_different_seeds_produce_different_values():
    vault1, _ = _vault_with("dev", "K", "v")
    vault2, _ = _vault_with("dev", "K", "v")
    r1 = shuffle_secret(vault1, "dev", "K", seed=1, length=32)
    r2 = shuffle_secret(vault2, "dev", "K", seed=2, length=32)
    assert r1.new_value != r2.new_value


def test_shuffle_unknown_charset_raises():
    vault, _ = _vault_with("dev", "K", "v")
    with pytest.raises(ShuffleError, match="Unknown charset"):
        shuffle_secret(vault, "dev", "K", charset="emoji")


def test_shuffle_zero_length_raises():
    vault, _ = _vault_with("dev", "K", "v")
    with pytest.raises(ShuffleError, match="length must be at least 1"):
        shuffle_secret(vault, "dev", "K", length=0)


def test_shuffle_missing_secret_raises():
    vault = _FakeVault({})
    with pytest.raises(ShuffleError, match="not found"):
        shuffle_secret(vault, "dev", "MISSING")


def test_shuffle_hex_charset_uses_only_hex_chars():
    vault, _ = _vault_with("dev", "K", "v")
    result = shuffle_secret(vault, "dev", "K", charset="hex", length=64, seed=0)
    allowed = set("0123456789abcdef")
    assert all(c in allowed for c in result.new_value)
