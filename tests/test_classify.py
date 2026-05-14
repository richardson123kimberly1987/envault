"""Tests for envault.classify."""
from __future__ import annotations

import pytest

from envault.classify import (
    CLASSIFICATION_LEVELS,
    ClassifyError,
    ClassifyResult,
    get_classification,
    list_by_classification,
    set_classification,
)


class _FakeEntry:
    def __init__(self, value="secret", classification=None):
        self._data = {"value": value}
        if classification:
            self._data["classification"] = classification

    def to_dict(self):
        return dict(self._data)

    def update_value(self, value, metadata=None):
        self._data["value"] = value
        if metadata:
            self._data.update(metadata)


class _FakeVault:
    def __init__(self, secrets=None):
        self._secrets = secrets or {}
        self.saved = False

    def get_secret(self, env, key):
        return self._secrets.get((env, key))

    def set_secret(self, env, key, entry):
        self._secrets[(env, key)] = entry

    def list_secrets(self, env):
        return [k for (e, k) in self._secrets if e == env]

    def save(self):
        self.saved = True


def test_classification_levels_not_empty():
    assert len(CLASSIFICATION_LEVELS) >= 2


def test_set_classification_returns_result():
    entry = _FakeEntry()
    vault = _FakeVault({("prod", "API_KEY"): entry})
    result = set_classification(vault, "prod", "API_KEY", "confidential")
    assert isinstance(result, ClassifyResult)
    assert result.level == "confidential"
    assert result.secret == "API_KEY"
    assert result.environment == "prod"


def test_set_classification_records_previous():
    entry = _FakeEntry(classification="internal")
    vault = _FakeVault({("prod", "API_KEY"): entry})
    result = set_classification(vault, "prod", "API_KEY", "restricted")
    assert result.previous == "internal"


def test_set_classification_invalid_level_raises():
    entry = _FakeEntry()
    vault = _FakeVault({("prod", "API_KEY"): entry})
    with pytest.raises(ClassifyError, match="Invalid classification level"):
        set_classification(vault, "prod", "API_KEY", "top-secret")


def test_set_classification_missing_secret_raises():
    vault = _FakeVault()
    with pytest.raises(ClassifyError, match="not found"):
        set_classification(vault, "prod", "MISSING", "public")


def test_get_classification_returns_set_level():
    entry = _FakeEntry(classification="restricted")
    vault = _FakeVault({("prod", "DB_PASS"): entry})
    result = get_classification(vault, "prod", "DB_PASS")
    assert result.level == "restricted"


def test_get_classification_defaults_to_internal():
    entry = _FakeEntry()
    vault = _FakeVault({("dev", "TOKEN"): entry})
    result = get_classification(vault, "dev", "TOKEN")
    assert result.level == "internal"


def test_get_classification_missing_secret_raises():
    vault = _FakeVault()
    with pytest.raises(ClassifyError):
        get_classification(vault, "dev", "NOPE")


def test_list_by_classification_returns_matching():
    vault = _FakeVault({
        ("prod", "A"): _FakeEntry(classification="confidential"),
        ("prod", "B"): _FakeEntry(classification="public"),
        ("prod", "C"): _FakeEntry(classification="confidential"),
    })
    results = list_by_classification(vault, "prod", "confidential")
    names = {r.secret for r in results}
    assert names == {"A", "C"}


def test_list_by_classification_invalid_level_raises():
    vault = _FakeVault()
    with pytest.raises(ClassifyError, match="Invalid classification level"):
        list_by_classification(vault, "prod", "ultra")


def test_classify_result_to_dict():
    r = ClassifyResult(secret="KEY", environment="prod", level="public", previous="internal")
    d = r.to_dict()
    assert d["secret"] == "KEY"
    assert d["level"] == "public"
    assert d["previous"] == "internal"
