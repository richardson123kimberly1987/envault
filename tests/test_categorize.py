"""Tests for envault.categorize."""
import pytest

from envault.categorize import (
    CATEGORIES,
    CategorizeError,
    CategorizeResult,
    list_by_category,
    set_category,
)


class _FakeEntry:
    def __init__(self, value="secret", category=None):
        self._data = {"value": value}
        if category:
            self._data["category"] = category

    def to_dict(self):
        return dict(self._data)

    def update_value(self, value, extra=None):
        self._data["value"] = value
        if extra:
            self._data.update(extra)


class _FakeVault:
    def __init__(self, secrets=None):
        self._secrets = secrets or {}
        self.saved = False

    def get_secret(self, env, name):
        return self._secrets.get((env, name))

    def set_secret(self, env, name, entry):
        self._secrets[(env, name)] = entry

    def list_secrets(self, env):
        return [k[1] for k in self._secrets if k[0] == env]

    def save(self):
        self.saved = True


def test_categories_constant_not_empty():
    assert len(CATEGORIES) > 0
    assert "api_key" in CATEGORIES
    assert "other" in CATEGORIES


def test_set_category_returns_result():
    entry = _FakeEntry("myval")
    vault = _FakeVault({("prod", "DB_URL"): entry})
    result = set_category(vault, "prod", "DB_URL", "database")
    assert isinstance(result, CategorizeResult)
    assert result.category == "database"
    assert result.secret == "DB_URL"
    assert result.environment == "prod"


def test_set_category_records_previous():
    entry = _FakeEntry("myval", category="token")
    vault = _FakeVault({("prod", "API_KEY"): entry})
    result = set_category(vault, "prod", "API_KEY", "api_key")
    assert result.previous == "token"


def test_set_category_no_previous():
    entry = _FakeEntry("myval")
    vault = _FakeVault({("prod", "API_KEY"): entry})
    result = set_category(vault, "prod", "API_KEY", "api_key")
    assert result.previous is None


def test_set_category_invalid_raises():
    entry = _FakeEntry("myval")
    vault = _FakeVault({("prod", "X"): entry})
    with pytest.raises(CategorizeError, match="Invalid category"):
        set_category(vault, "prod", "X", "unknown_type")


def test_set_category_missing_secret_raises():
    vault = _FakeVault()
    with pytest.raises(CategorizeError, match="not found"):
        set_category(vault, "prod", "MISSING", "token")


def test_list_by_category_all():
    vault = _FakeVault({
        ("dev", "A"): _FakeEntry(category="token"),
        ("dev", "B"): _FakeEntry(category="api_key"),
    })
    items = list_by_category(vault, "dev")
    assert len(items) == 2


def test_list_by_category_filtered():
    vault = _FakeVault({
        ("dev", "A"): _FakeEntry(category="token"),
        ("dev", "B"): _FakeEntry(category="api_key"),
    })
    items = list_by_category(vault, "dev", category="token")
    assert len(items) == 1
    assert items[0]["secret"] == "A"


def test_categorize_result_to_dict():
    r = CategorizeResult(secret="X", environment="prod", category="token", previous="other")
    d = r.to_dict()
    assert d["secret"] == "X"
    assert d["category"] == "token"
    assert d["previous"] == "other"
