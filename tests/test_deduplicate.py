"""Tests for envault.deduplicate."""
from __future__ import annotations

import pytest

from envault.deduplicate import DeduplicateError, DeduplicateResult, find_duplicates


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, encrypted_value: str):
        self._value = encrypted_value

    def to_dict(self):
        return {"value": self._value}


class _FakeVault:
    def __init__(self, data):
        # data: {env: {key: plaintext}}
        self._data = data

    def list_environments(self):
        return list(self._data.keys())

    def list_secrets(self, env):
        return list(self._data.get(env, {}).keys())

    def get_secret(self, env, key):
        val = self._data.get(env, {}).get(key)
        if val is None:
            return None
        # Store plaintext directly as the "encrypted" value so our fake
        # decrypt (below) can return it unchanged.
        return _FakeEntry(val)


# Patch decrypt to be an identity function for tests
import envault.deduplicate as _mod


@pytest.fixture(autouse=True)
def _patch_decrypt(monkeypatch):
    monkeypatch.setattr(_mod, "__builtins__", __builtins__)  # no-op keep builtins
    import envault.crypto as _crypto
    monkeypatch.setattr(_crypto, "decrypt", lambda ciphertext, _passphrase: ciphertext)
    # Also patch the import inside find_duplicates
    import importlib, sys
    # Re-import to pick up monkeypatched crypto
    yield


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_deduplicate_result_to_dict_empty():
    result = DeduplicateResult()
    d = result.to_dict()
    assert d["total_groups"] == 0
    assert d["total_duplicates"] == 0
    assert d["duplicates"] == {}


def test_no_duplicates_returns_empty(monkeypatch):
    import envault.crypto as _crypto
    monkeypatch.setattr(_crypto, "decrypt", lambda c, _p: c)
    vault = _FakeVault({"prod": {"KEY_A": "val1"}, "dev": {"KEY_B": "val2"}})
    result = find_duplicates(vault, "pass")
    assert result.duplicates == {}


def test_finds_duplicate_across_environments(monkeypatch):
    import envault.crypto as _crypto
    monkeypatch.setattr(_crypto, "decrypt", lambda c, _p: c)
    vault = _FakeVault({
        "prod": {"DB_PASS": "secret123"},
        "dev": {"DB_PASS": "secret123"},
    })
    result = find_duplicates(vault, "pass")
    assert len(result.duplicates) == 1
    pairs = next(iter(result.duplicates.values()))
    envs = {env for env, _ in pairs}
    assert envs == {"prod", "dev"}


def test_finds_duplicate_within_same_environment(monkeypatch):
    import envault.crypto as _crypto
    monkeypatch.setattr(_crypto, "decrypt", lambda c, _p: c)
    vault = _FakeVault({
        "prod": {"KEY_A": "shared", "KEY_B": "shared"},
    })
    result = find_duplicates(vault, "pass")
    assert len(result.duplicates) == 1
    pairs = next(iter(result.duplicates.values()))
    keys = {key for _, key in pairs}
    assert keys == {"KEY_A", "KEY_B"}


def test_decrypt_error_raises_deduplicate_error(monkeypatch):
    import envault.crypto as _crypto
    monkeypatch.setattr(_crypto, "decrypt", lambda c, _p: (_ for _ in ()).throw(ValueError("bad")))
    vault = _FakeVault({"prod": {"KEY": "val"}})
    with pytest.raises(DeduplicateError, match="Failed to decrypt"):
        find_duplicates(vault, "wrong")


def test_hash_keys_do_not_expose_plaintext(monkeypatch):
    import envault.crypto as _crypto
    monkeypatch.setattr(_crypto, "decrypt", lambda c, _p: c)
    vault = _FakeVault({
        "prod": {"A": "supersecret"},
        "dev": {"A": "supersecret"},
    })
    result = find_duplicates(vault, "pass")
    for h in result.duplicates:
        assert "supersecret" not in h
