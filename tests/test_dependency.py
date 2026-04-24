"""Tests for envault.dependency."""
import json
import pytest

from envault.dependency import (
    DEPENDENCY_KEY,
    DependencyError,
    DependencyResult,
    add_dependency,
    list_dependencies,
    remove_dependency,
    resolve_order,
)


class _FakeEntry:
    def __init__(self, value: str):
        self._value = value

    def to_dict(self):
        return {"value": self._value}


class _FakeVault:
    def __init__(self):
        self._store: dict = {}

    def get_secret(self, name, env):
        return self._store.get((name, env))

    def set_secret(self, name, env, value):
        self._store[(name, env)] = value

    def list_secrets(self, env):
        return [k[0] for k in self._store if k[1] == env and k[0] != DEPENDENCY_KEY]

    def save(self):
        pass


@pytest.fixture()
def vault():
    v = _FakeVault()
    v.set_secret("DB_URL", "prod", "postgres://localhost/db")
    v.set_secret("DB_PASS", "prod", "s3cr3t")
    v.set_secret("APP_KEY", "prod", "appkey")
    return v


def test_dependency_result_to_dict():
    r = DependencyResult(secret="A", environment="prod", depends_on=["B", "C"])
    d = r.to_dict()
    assert d["secret"] == "A"
    assert d["environment"] == "prod"
    assert d["depends_on"] == ["B", "C"]


def test_add_dependency_returns_result(vault):
    result = add_dependency(vault, "DB_URL", "prod", "DB_PASS")
    assert isinstance(result, DependencyResult)
    assert "DB_PASS" in result.depends_on


def test_add_dependency_persists(vault):
    add_dependency(vault, "DB_URL", "prod", "DB_PASS")
    result = list_dependencies(vault, "DB_URL", "prod")
    assert "DB_PASS" in result.depends_on


def test_add_dependency_idempotent(vault):
    add_dependency(vault, "DB_URL", "prod", "DB_PASS")
    add_dependency(vault, "DB_URL", "prod", "DB_PASS")
    result = list_dependencies(vault, "DB_URL", "prod")
    assert result.depends_on.count("DB_PASS") == 1


def test_add_dependency_missing_secret_raises(vault):
    with pytest.raises(DependencyError, match="not found"):
        add_dependency(vault, "MISSING", "prod", "DB_PASS")


def test_add_dependency_missing_dep_raises(vault):
    with pytest.raises(DependencyError, match="not found"):
        add_dependency(vault, "DB_URL", "prod", "MISSING")


def test_remove_dependency(vault):
    add_dependency(vault, "DB_URL", "prod", "DB_PASS")
    result = remove_dependency(vault, "DB_URL", "prod", "DB_PASS")
    assert "DB_PASS" not in result.depends_on


def test_remove_nonexistent_dependency_raises(vault):
    with pytest.raises(DependencyError, match="not found"):
        remove_dependency(vault, "DB_URL", "prod", "DB_PASS")


def test_list_dependencies_empty(vault):
    result = list_dependencies(vault, "DB_URL", "prod")
    assert result.depends_on == []


def test_resolve_order_no_deps(vault):
    order = resolve_order(vault, "prod")
    assert set(order) == {"DB_URL", "DB_PASS", "APP_KEY"}


def test_resolve_order_respects_deps(vault):
    add_dependency(vault, "DB_URL", "prod", "DB_PASS")
    order = resolve_order(vault, "prod")
    assert order.index("DB_PASS") < order.index("DB_URL")


def test_resolve_order_circular_raises(vault):
    add_dependency(vault, "DB_URL", "prod", "DB_PASS")
    add_dependency(vault, "DB_PASS", "prod", "DB_URL")
    with pytest.raises(DependencyError, match="Circular"):
        resolve_order(vault, "prod")
