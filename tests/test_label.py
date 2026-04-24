"""Tests for envault.label."""
from __future__ import annotations

import pytest

from envault.label import (
    LabelError,
    LabelResult,
    set_label,
    remove_label,
    list_labels,
    LABEL_KEY_MAX_LEN,
    LABEL_VALUE_MAX_LEN,
)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, data: dict):
        self._data = data

    def to_dict(self) -> dict:
        return dict(self._data)


class _FakeVault:
    def __init__(self):
        self._store: dict = {}

    def get_secret(self, env: str, secret: str):
        return self._store.get((env, secret))

    def set_secret(self, env: str, secret: str, data: dict):
        self._store[(env, secret)] = _FakeEntry(data)


@pytest.fixture()
def vault():
    v = _FakeVault()
    v.set_secret("prod", "DB_PASS", {"value": "s3cr3t", "labels": {}})
    return v


# ---------------------------------------------------------------------------
# LabelResult.to_dict
# ---------------------------------------------------------------------------

def test_label_result_to_dict():
    r = LabelResult(secret="K", environment="e", labels={"tier": "gold"}, changed=True)
    d = r.to_dict()
    assert d["secret"] == "K"
    assert d["environment"] == "e"
    assert d["labels"] == {"tier": "gold"}
    assert d["changed"] is True


# ---------------------------------------------------------------------------
# set_label
# ---------------------------------------------------------------------------

def test_set_label_adds_new_label(vault):
    result = set_label(vault, "prod", "DB_PASS", "owner", "alice")
    assert result.labels["owner"] == "alice"
    assert result.changed is True


def test_set_label_updates_existing_label(vault):
    set_label(vault, "prod", "DB_PASS", "owner", "alice")
    result = set_label(vault, "prod", "DB_PASS", "owner", "bob")
    assert result.labels["owner"] == "bob"
    assert result.changed is True


def test_set_label_no_change_when_same_value(vault):
    set_label(vault, "prod", "DB_PASS", "owner", "alice")
    result = set_label(vault, "prod", "DB_PASS", "owner", "alice")
    assert result.changed is False


def test_set_label_missing_secret_raises(vault):
    with pytest.raises(LabelError, match="not found"):
        set_label(vault, "prod", "MISSING", "k", "v")


def test_set_label_empty_key_raises(vault):
    with pytest.raises(LabelError, match="key"):
        set_label(vault, "prod", "DB_PASS", "", "v")


def test_set_label_key_too_long_raises(vault):
    with pytest.raises(LabelError, match="key"):
        set_label(vault, "prod", "DB_PASS", "x" * (LABEL_KEY_MAX_LEN + 1), "v")


def test_set_label_value_too_long_raises(vault):
    with pytest.raises(LabelError, match="value"):
        set_label(vault, "prod", "DB_PASS", "k", "x" * (LABEL_VALUE_MAX_LEN + 1))


# ---------------------------------------------------------------------------
# remove_label
# ---------------------------------------------------------------------------

def test_remove_label_removes_existing(vault):
    set_label(vault, "prod", "DB_PASS", "tier", "gold")
    result = remove_label(vault, "prod", "DB_PASS", "tier")
    assert "tier" not in result.labels
    assert result.changed is True


def test_remove_label_missing_key_raises(vault):
    with pytest.raises(LabelError, match="not found"):
        remove_label(vault, "prod", "DB_PASS", "nonexistent")


def test_remove_label_missing_secret_raises(vault):
    with pytest.raises(LabelError, match="not found"):
        remove_label(vault, "prod", "GHOST", "k")


# ---------------------------------------------------------------------------
# list_labels
# ---------------------------------------------------------------------------

def test_list_labels_returns_all(vault):
    set_label(vault, "prod", "DB_PASS", "a", "1")
    set_label(vault, "prod", "DB_PASS", "b", "2")
    result = list_labels(vault, "prod", "DB_PASS")
    assert result.labels == {"a": "1", "b": "2"}
    assert result.changed is False


def test_list_labels_empty_when_none_set(vault):
    result = list_labels(vault, "prod", "DB_PASS")
    assert result.labels == {}


def test_list_labels_missing_secret_raises(vault):
    with pytest.raises(LabelError, match="not found"):
        list_labels(vault, "prod", "NO_SUCH")
