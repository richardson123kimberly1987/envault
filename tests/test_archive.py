"""Tests for envault.archive."""
from __future__ import annotations

import pytest
from envault.archive import (
    ArchiveEntry,
    ArchiveError,
    ARCHIVE_KEY,
    archive_secret,
    restore_secret,
    list_archive,
)


class _FakeEntry:
    def __init__(self, value: str):
        self.value = value

    def to_dict(self):
        return {"value": self.value}


class _FakeVault:
    def __init__(self):
        self._data: dict = {}
        self._secrets: dict = {}

    def get_secret(self, env, key):
        return self._secrets.get((env, key))

    def set_secret(self, env, key, value):
        self._secrets[(env, key)] = _FakeEntry(value)

    def delete_secret(self, env, key):
        self._secrets.pop((env, key), None)

    def set_raw(self, key, value):
        self._data[key] = value

    def set_secret_from_dict(self, env, key, d):
        self._secrets[(env, key)] = _FakeEntry(d["value"])


@pytest.fixture
def vault():
    v = _FakeVault()
    v.set_secret("prod", "DB_PASS", "s3cr3t")
    return v


def test_archive_entry_to_dict_round_trip():
    ae = ArchiveEntry(environment="prod", key="X", secret_dict={"value": "v"})
    d = ae.to_dict()
    ae2 = ArchiveEntry.from_dict(d)
    assert ae2.environment == "prod"
    assert ae2.key == "X"
    assert ae2.secret_dict == {"value": "v"}
    assert ae2.archived_at == ae.archived_at


def test_archive_secret_removes_from_vault(vault):
    ae = archive_secret(vault, "prod", "DB_PASS")
    assert isinstance(ae, ArchiveEntry)
    assert vault.get_secret("prod", "DB_PASS") is None


def test_archive_secret_stores_in_raw(vault):
    archive_secret(vault, "prod", "DB_PASS")
    assert len(vault._data[ARCHIVE_KEY]) == 1
    assert vault._data[ARCHIVE_KEY][0]["key"] == "DB_PASS"


def test_archive_missing_secret_raises(vault):
    with pytest.raises(ArchiveError):
        archive_secret(vault, "prod", "MISSING")


def test_restore_secret_puts_back(vault):
    archive_secret(vault, "prod", "DB_PASS")
    ae = restore_secret(vault, "prod", "DB_PASS")
    assert isinstance(ae, ArchiveEntry)
    entry = vault.get_secret("prod", "DB_PASS")
    assert entry is not None
    assert entry.value == "s3cr3t"


def test_restore_removes_from_archive(vault):
    archive_secret(vault, "prod", "DB_PASS")
    restore_secret(vault, "prod", "DB_PASS")
    assert vault._data[ARCHIVE_KEY] == []


def test_restore_missing_raises(vault):
    with pytest.raises(ArchiveError):
        restore_secret(vault, "prod", "NOPE")


def test_list_archive_empty(vault):
    assert list_archive(vault) == []


def test_list_archive_returns_entries(vault):
    archive_secret(vault, "prod", "DB_PASS")
    entries = list_archive(vault)
    assert len(entries) == 1
    assert entries[0].key == "DB_PASS"
