"""Tests for envault.namespace."""
import pytest

from envault.namespace import (
    NamespaceError,
    NamespaceResult,
    list_in_namespace,
    move_to_namespace,
    remove_from_namespace,
)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str):
        self._value = value

    def to_dict(self):
        return {"value": self._value}


class _FakeVault:
    def __init__(self, secrets: dict | None = None):
        self._secrets: dict[str, _FakeEntry] = secrets or {}
        self.saved = False

    def list_secrets(self, environment: str):
        return list(self._secrets.keys())

    def get_secret(self, environment: str, key: str):
        return self._secrets.get(key)

    def set_secret(self, environment: str, key: str, value: str):
        self._secrets[key] = _FakeEntry(value)

    def delete_secret(self, environment: str, key: str):
        self._secrets.pop(key, None)

    def save(self):
        self.saved = True


# ---------------------------------------------------------------------------
# NamespaceResult
# ---------------------------------------------------------------------------

def test_namespace_result_to_dict():
    r = NamespaceResult(namespace="infra", secrets=["infra/DB_URL"], action="list")
    d = r.to_dict()
    assert d["namespace"] == "infra"
    assert d["secrets"] == ["infra/DB_URL"]
    assert d["action"] == "list"


# ---------------------------------------------------------------------------
# list_in_namespace
# ---------------------------------------------------------------------------

def test_list_in_namespace_returns_matching_keys():
    vault = _FakeVault({"infra/DB_URL": _FakeEntry("x"), "app/KEY": _FakeEntry("y"), "TOP": _FakeEntry("z")})
    result = list_in_namespace(vault, "prod", "infra")
    assert result.secrets == ["infra/DB_URL"]
    assert result.action == "list"


def test_list_in_namespace_empty_when_no_match():
    vault = _FakeVault({"app/KEY": _FakeEntry("y")})
    result = list_in_namespace(vault, "prod", "infra")
    assert result.secrets == []


def test_list_in_namespace_invalid_raises():
    vault = _FakeVault()
    with pytest.raises(NamespaceError):
        list_in_namespace(vault, "prod", "bad ns!")


# ---------------------------------------------------------------------------
# move_to_namespace
# ---------------------------------------------------------------------------

def test_move_to_namespace_renames_key():
    vault = _FakeVault({"DB_URL": _FakeEntry("postgres://")})
    result = move_to_namespace(vault, "prod", "DB_URL", "infra")
    assert result.secrets == ["infra/DB_URL"]
    assert vault.get_secret("prod", "infra/DB_URL") is not None
    assert vault.get_secret("prod", "DB_URL") is None
    assert vault.saved


def test_move_to_namespace_missing_secret_raises():
    vault = _FakeVault()
    with pytest.raises(NamespaceError, match="not found"):
        move_to_namespace(vault, "prod", "MISSING", "infra")


def test_move_to_namespace_existing_destination_raises_without_overwrite():
    vault = _FakeVault({"DB_URL": _FakeEntry("a"), "infra/DB_URL": _FakeEntry("b")})
    with pytest.raises(NamespaceError, match="already exists"):
        move_to_namespace(vault, "prod", "DB_URL", "infra")


def test_move_to_namespace_overwrite_succeeds():
    vault = _FakeVault({"DB_URL": _FakeEntry("new"), "infra/DB_URL": _FakeEntry("old")})
    result = move_to_namespace(vault, "prod", "DB_URL", "infra", overwrite=True)
    assert result.secrets == ["infra/DB_URL"]


# ---------------------------------------------------------------------------
# remove_from_namespace
# ---------------------------------------------------------------------------

def test_remove_from_namespace_strips_prefix():
    vault = _FakeVault({"infra/DB_URL": _FakeEntry("postgres://")})
    result = remove_from_namespace(vault, "prod", "infra/DB_URL")
    assert result.secrets == ["DB_URL"]
    assert vault.get_secret("prod", "DB_URL") is not None
    assert vault.get_secret("prod", "infra/DB_URL") is None
    assert vault.saved


def test_remove_from_namespace_no_slash_raises():
    vault = _FakeVault({"DB_URL": _FakeEntry("x")})
    with pytest.raises(NamespaceError, match="does not appear"):
        remove_from_namespace(vault, "prod", "DB_URL")


def test_remove_from_namespace_wrong_namespace_raises():
    vault = _FakeVault({"infra/DB_URL": _FakeEntry("x")})
    with pytest.raises(NamespaceError, match="not 'app'"):
        remove_from_namespace(vault, "prod", "infra/DB_URL", namespace="app")


def test_remove_from_namespace_missing_secret_raises():
    vault = _FakeVault()
    with pytest.raises(NamespaceError, match="not found"):
        remove_from_namespace(vault, "prod", "infra/MISSING")
