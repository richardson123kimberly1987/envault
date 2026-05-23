"""Tests for envault.chain."""
from __future__ import annotations

import base64

import pytest

from envault.chain import (
    CHAIN_STEPS,
    ChainError,
    ChainResult,
    _apply_step,
    chain_secret,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, ciphertext: str):
        self._ct = ciphertext

    def to_dict(self):
        return {"value": self._ct}


class _FakeVault:
    def __init__(self, entry):
        self._entry = entry
        self.saved = False
        self.last_set: dict = {}

    def get_secret(self, env, secret):
        return self._entry

    def set_secret(self, env, secret, value, passphrase):
        self.last_set = {"env": env, "secret": secret, "value": value}

    def save(self):
        self.saved = True


# ---------------------------------------------------------------------------
# Unit tests – _apply_step
# ---------------------------------------------------------------------------

def test_apply_step_upper():
    assert _apply_step("hello", "upper") == "HELLO"


def test_apply_step_lower():
    assert _apply_step("WORLD", "lower") == "world"


def test_apply_step_strip():
    assert _apply_step("  hi  ", "strip") == "hi"


def test_apply_step_reverse():
    assert _apply_step("abcd", "reverse") == "dcba"


def test_apply_step_base64_encode():
    result = _apply_step("secret", "base64_encode")
    assert result == base64.b64encode(b"secret").decode()


def test_apply_step_base64_decode():
    encoded = base64.b64encode(b"secret").decode()
    assert _apply_step(encoded, "base64_decode") == "secret"


def test_apply_step_unknown_raises():
    with pytest.raises(ChainError, match="Unknown chain step"):
        _apply_step("value", "nonexistent")


# ---------------------------------------------------------------------------
# Unit tests – chain_secret
# ---------------------------------------------------------------------------

def _make_vault_and_crypto(plaintext: str):
    """Return a fake vault whose entry decrypts to *plaintext*."""
    from envault.crypto import encrypt

    passphrase = "test-pass"
    ciphertext = encrypt(plaintext, passphrase)
    entry = _FakeEntry(ciphertext)
    vault = _FakeVault(entry)
    return vault, passphrase


def test_chain_secret_single_step():
    vault, passphrase = _make_vault_and_crypto("hello")
    result = chain_secret(vault, "dev", "MY_KEY", ["upper"], passphrase)
    assert result.result == "HELLO"
    assert result.original == "hello"
    assert result.steps == ["upper"]


def test_chain_secret_multiple_steps():
    vault, passphrase = _make_vault_and_crypto("  Hello  ")
    result = chain_secret(vault, "dev", "MY_KEY", ["strip", "lower"], passphrase)
    assert result.result == "hello"


def test_chain_secret_saves_by_default():
    vault, passphrase = _make_vault_and_crypto("abc")
    chain_secret(vault, "dev", "MY_KEY", ["upper"], passphrase)
    assert vault.saved is True
    assert vault.last_set["value"] == "ABC"


def test_chain_secret_dry_run_does_not_save():
    vault, passphrase = _make_vault_and_crypto("abc")
    chain_secret(vault, "dev", "MY_KEY", ["upper"], passphrase, save=False)
    assert vault.saved is False
    assert vault.last_set == {}


def test_chain_secret_missing_entry_raises():
    vault = _FakeVault(None)
    with pytest.raises(ChainError, match="not found"):
        chain_secret(vault, "dev", "MISSING", ["upper"], "pass")


def test_chain_secret_invalid_step_raises():
    vault, passphrase = _make_vault_and_crypto("abc")
    with pytest.raises(ChainError, match="Unknown chain step"):
        chain_secret(vault, "dev", "MY_KEY", ["bad_step"], passphrase)


def test_chain_result_to_dict():
    r = ChainResult(secret="K", env="dev", steps=["upper"], original="a", result="A")
    d = r.to_dict()
    assert d == {"secret": "K", "env": "dev", "steps": ["upper"], "original": "a", "result": "A"}


def test_chain_steps_constant_not_empty():
    assert len(CHAIN_STEPS) > 0
