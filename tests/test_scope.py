"""Tests for envault.scope."""
import pytest

from envault.scope import (
    ScopeError,
    ScopeResult,
    add_scope,
    remove_scope,
    list_scopes,
    filter_by_scope,
)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str, scopes=None):
        self._data = {"value": value, "scopes": scopes or []}

    def to_dict(self):
        return dict(self._data)


class _FakeVault:
    def __init__(self):
        self._store: dict = {}  # (env, secret) -> _FakeEntry
        self.saved = False

    def get_secret(self, env, secret):
        return self._store.get((env, secret))

    def set_secret(self, env, secret, value, metadata=None):
        scopes = (metadata or {}).get("scopes", [])
        self._store[(env, secret)] = _FakeEntry(value, scopes)

    def list_secrets(self, env):
        return [k[1] for k in self._store if k[0] == env]

    def save(self):
        self.saved = True


@pytest.fixture()
def vault():
    v = _FakeVault()
    v.set_secret("prod", "DB_PASS", "secret123")
    return v


# ---------------------------------------------------------------------------
# ScopeResult.to_dict
# ---------------------------------------------------------------------------

def test_scope_result_to_dict():
    r = ScopeResult(secret="KEY", environment="dev", scopes=["svc-a"], action="added")
    d = r.to_dict()
    assert d["secret"] == "KEY"
    assert d["environment"] == "dev"
    assert d["scopes"] == ["svc-a"]
    assert d["action"] == "added"


# ---------------------------------------------------------------------------
# add_scope
# ---------------------------------------------------------------------------

def test_add_scope_returns_result(vault):
    result = add_scope(vault, "prod", "DB_PASS", "backend")
    assert isinstance(result, ScopeResult)
    assert result.action == "added"
    assert "backend" in result.scopes


def test_add_scope_saves_vault(vault):
    add_scope(vault, "prod", "DB_PASS", "backend")
    assert vault.saved


def test_add_scope_idempotent(vault):
    add_scope(vault, "prod", "DB_PASS", "backend")
    result = add_scope(vault, "prod", "DB_PASS", "backend")
    assert result.scopes.count("backend") == 1


def test_add_scope_missing_secret_raises(vault):
    with pytest.raises(ScopeError, match="not found"):
        add_scope(vault, "prod", "MISSING", "backend")


# ---------------------------------------------------------------------------
# remove_scope
# ---------------------------------------------------------------------------

def test_remove_scope_removes_correctly(vault):
    add_scope(vault, "prod", "DB_PASS", "svc-a")
    result = remove_scope(vault, "prod", "DB_PASS", "svc-a")
    assert "svc-a" not in result.scopes
    assert result.action == "removed"


def test_remove_scope_not_present_raises(vault):
    with pytest.raises(ScopeError, match="not assigned"):
        remove_scope(vault, "prod", "DB_PASS", "nonexistent")


def test_remove_scope_missing_secret_raises(vault):
    with pytest.raises(ScopeError, match="not found"):
        remove_scope(vault, "prod", "GHOST", "svc")


# ---------------------------------------------------------------------------
# list_scopes
# ---------------------------------------------------------------------------

def test_list_scopes_empty(vault):
    result = list_scopes(vault, "prod", "DB_PASS")
    assert result.scopes == []
    assert result.action == "listed"


def test_list_scopes_after_add(vault):
    add_scope(vault, "prod", "DB_PASS", "alpha")
    add_scope(vault, "prod", "DB_PASS", "beta")
    result = list_scopes(vault, "prod", "DB_PASS")
    assert set(result.scopes) == {"alpha", "beta"}


def test_list_scopes_missing_secret_raises(vault):
    with pytest.raises(ScopeError):
        list_scopes(vault, "prod", "NOPE")


# ---------------------------------------------------------------------------
# filter_by_scope
# ---------------------------------------------------------------------------

def test_filter_by_scope_returns_matching(vault):
    vault.set_secret("prod", "API_KEY", "xyz")
    add_scope(vault, "prod", "DB_PASS", "frontend")
    add_scope(vault, "prod", "API_KEY", "frontend")
    names = filter_by_scope(vault, "prod", "frontend")
    assert set(names) == {"DB_PASS", "API_KEY"}


def test_filter_by_scope_no_match_returns_empty(vault):
    names = filter_by_scope(vault, "prod", "unknown-scope")
    assert names == []
