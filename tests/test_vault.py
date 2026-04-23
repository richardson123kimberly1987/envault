"""Tests for envault.vault module."""

import json
from pathlib import Path

import pytest

from envault.crypto import encrypt
from envault.vault import Vault, VaultError

PASSPHRASE = "test-passphrase-123"


@pytest.fixture
def tmp_vault(tmp_path):
    """Return a fresh Vault backed by a temp file."""
    vault_file = tmp_path / ".envault"
    return Vault(path=vault_file, passphrase=PASSPHRASE)


def test_vault_starts_empty(tmp_vault):
    tmp_vault.load()
    assert tmp_vault.list_envs() == []


def test_set_and_get_secret(tmp_vault):
    tmp_vault.load()
    tmp_vault.set_secret("production", "DB_PASSWORD", "s3cr3t")
    assert tmp_vault.get_secret("production", "DB_PASSWORD") == "s3cr3t"


def test_get_missing_secret_returns_none(tmp_vault):
    tmp_vault.load()
    assert tmp_vault.get_secret("staging", "MISSING_KEY") is None


def test_save_and_reload(tmp_vault):
    tmp_vault.load()
    tmp_vault.set_secret("dev", "API_KEY", "abc123")
    tmp_vault.save()

    vault2 = Vault(path=tmp_vault.path, passphrase=PASSPHRASE)
    vault2.load()
    assert vault2.get_secret("dev", "API_KEY") == "abc123"


def test_save_creates_encrypted_file(tmp_vault):
    tmp_vault.load()
    tmp_vault.set_secret("prod", "SECRET", "value")
    tmp_vault.save()

    raw = tmp_vault.path.read_text()
    # Raw content must not contain the plaintext value
    assert "value" not in raw


def test_delete_existing_secret(tmp_vault):
    tmp_vault.load()
    tmp_vault.set_secret("prod", "KEY", "val")
    removed = tmp_vault.delete_secret("prod", "KEY")
    assert removed is True
    assert tmp_vault.get_secret("prod", "KEY") is None


def test_delete_missing_secret_returns_false(tmp_vault):
    tmp_vault.load()
    assert tmp_vault.delete_secret("prod", "NONEXISTENT") is False


def test_list_keys(tmp_vault):
    tmp_vault.load()
    tmp_vault.set_secret("staging", "A", "1")
    tmp_vault.set_secret("staging", "B", "2")
    assert sorted(tmp_vault.list_keys("staging")) == ["A", "B"]


def test_list_keys_missing_env_returns_empty(tmp_vault):
    """list_keys on a non-existent environment should return an empty list."""
    tmp_vault.load()
    assert tmp_vault.list_keys("nonexistent") == []


def test_list_envs(tmp_vault):
    tmp_vault.load()
    tmp_vault.set_secret("dev", "X", "1")
    tmp_vault.set_secret("prod", "Y", "2")
    assert sorted(tmp_vault.list_envs()) == ["dev", "prod"]


def test_export_env(tmp_vault):
    tmp_vault.load()
    tmp_vault.set_secret("dev", "FOO", "bar")
    tmp_vault.set_secret("dev", "BAZ", "qux")
    exported = tmp_vault.export_env("dev")
    assert exported == {"FOO": "bar", "BAZ": "qux"}


def test_export_env_missing_env_returns_empty(tmp_vault):
    """export_env on a non-existent environment should return an empty dict."""
    tmp_vault.load()
    assert tmp_vault.export_env("nonexistent") == {}


def test_load_wrong_passphrase_raises(tmp_vault):
    tmp_vault.load()
    tmp_vault.set_secret("prod", "KEY", "val")
    tmp_vault.save()

    vault2 = Vault(path=tmp_vault.path, passphrase="wrong-passphrase")
    with pytest.raises(VaultError):
        vault2.load()
