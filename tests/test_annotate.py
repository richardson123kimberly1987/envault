"""Tests for envault.annotate."""
from __future__ import annotations

import pytest

from envault.annotate import (
    AnnotateError,
    AnnotateResult,
    ANNOTATION_MAX_LENGTH,
    set_annotation,
    remove_annotation,
    get_annotation,
)


class _FakeEntry:
    def __init__(self, value: str = "s3cr3t", annotation: str | None = None):
        self._data: dict = {"value": value, "annotation": annotation}
        self._extra: dict = {}

    def to_dict(self) -> dict:
        return dict(self._data)

    def update_value(self, value: str, extra: dict | None = None) -> None:
        self._data["value"] = value
        if extra:
            self._data.update(extra)


class _FakeVault:
    def __init__(self, entry: _FakeEntry | None = None):
        self._entry = entry
        self.saved = False

    def get_secret(self, environment: str, secret: str) -> _FakeEntry | None:
        return self._entry

    def save(self) -> None:
        self.saved = True


@pytest.fixture()
def entry() -> _FakeEntry:
    return _FakeEntry()


@pytest.fixture()
def vault(entry: _FakeEntry) -> _FakeVault:
    return _FakeVault(entry=entry)


def test_annotate_result_to_dict():
    r = AnnotateResult(secret="KEY", environment="prod", annotation="note", previous=None)
    d = r.to_dict()
    assert d["secret"] == "KEY"
    assert d["environment"] == "prod"
    assert d["annotation"] == "note"
    assert d["previous"] is None


def test_set_annotation_stores_value(vault, entry):
    result = set_annotation(vault, "prod", "KEY", "my note")
    assert result.annotation == "my note"
    assert result.previous is None
    assert vault.saved


def test_set_annotation_returns_previous(vault, entry):
    entry._data["annotation"] = "old note"
    result = set_annotation(vault, "prod", "KEY", "new note")
    assert result.previous == "old note"
    assert result.annotation == "new note"


def test_set_annotation_too_long_raises(vault):
    with pytest.raises(AnnotateError, match="maximum length"):
        set_annotation(vault, "prod", "KEY", "x" * (ANNOTATION_MAX_LENGTH + 1))


def test_set_annotation_missing_secret_raises():
    v = _FakeVault(entry=None)
    with pytest.raises(AnnotateError, match="not found"):
        set_annotation(v, "prod", "MISSING", "note")


def test_remove_annotation_clears_value(vault, entry):
    entry._data["annotation"] = "to remove"
    result = remove_annotation(vault, "prod", "KEY")
    assert result.previous == "to remove"
    assert result.annotation == ""
    assert vault.saved


def test_remove_annotation_missing_secret_raises():
    v = _FakeVault(entry=None)
    with pytest.raises(AnnotateError, match="not found"):
        remove_annotation(v, "prod", "MISSING")


def test_get_annotation_returns_value(vault, entry):
    entry._data["annotation"] = "hello"
    assert get_annotation(vault, "prod", "KEY") == "hello"


def test_get_annotation_returns_none_when_unset(vault):
    assert get_annotation(vault, "prod", "KEY") is None


def test_get_annotation_missing_secret_raises():
    v = _FakeVault(entry=None)
    with pytest.raises(AnnotateError, match="not found"):
        get_annotation(v, "prod", "MISSING")
