"""Tests for envault.splice."""
from __future__ import annotations

import pytest

from envault.splice import SpliceError, SpliceResult, splice_secret


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str) -> None:
        self._value = value

    def decrypt(self, passphrase: str) -> str:  # noqa: ARG002
        return self._value

    def update_value(self, new_value: str, passphrase: str) -> None:  # noqa: ARG002
        self._value = new_value

    def to_dict(self) -> dict:
        return {"value": self._value}


class _FakeVault:
    def __init__(self, secrets: dict[tuple[str, str], _FakeEntry]) -> None:
        self._secrets = secrets
        self.saved: list[tuple[str, str, _FakeEntry]] = []

    def get_secret(self, environment: str, secret: str) -> _FakeEntry | None:
        return self._secrets.get((environment, secret))

    def set_secret(self, environment: str, secret: str, entry: _FakeEntry) -> None:
        self._secrets[(environment, secret)] = entry
        self.saved.append((environment, secret, entry))


_PASS = "test-pass"


# ---------------------------------------------------------------------------
# SpliceResult.to_dict
# ---------------------------------------------------------------------------

def test_splice_result_to_dict() -> None:
    r = SpliceResult(
        secret="KEY", environment="prod",
        original="hello world", spliced="hello WORLD",
        start=6, end=11, replacement="WORLD",
    )
    d = r.to_dict()
    assert d["secret"] == "KEY"
    assert d["spliced"] == "hello WORLD"
    assert d["start"] == 6
    assert d["end"] == 11


# ---------------------------------------------------------------------------
# splice_secret – happy path
# ---------------------------------------------------------------------------

def test_splice_replaces_middle() -> None:
    entry = _FakeEntry("hello world")
    vault = _FakeVault({("prod", "MSG"): entry})
    result = splice_secret(vault, "prod", "MSG", 6, 11, "WORLD", _PASS)
    assert result.spliced == "hello WORLD"
    assert result.original == "hello world"
    assert entry._value == "hello WORLD"


def test_splice_inserts_at_position() -> None:
    entry = _FakeEntry("foobar")
    vault = _FakeVault({("dev", "K"): entry})
    result = splice_secret(vault, "dev", "K", 3, 3, "---", _PASS)
    assert result.spliced == "foo---bar"


def test_splice_deletes_segment() -> None:
    entry = _FakeEntry("ab123cd")
    vault = _FakeVault({("dev", "K"): entry})
    result = splice_secret(vault, "dev", "K", 2, 5, "", _PASS)
    assert result.spliced == "abcd"


def test_splice_saves_to_vault() -> None:
    entry = _FakeEntry("secret")
    vault = _FakeVault({("prod", "S"): entry})
    splice_secret(vault, "prod", "S", 0, 3, "XXX", _PASS)
    assert len(vault.saved) == 1
    assert vault.saved[0][0] == "prod"
    assert vault.saved[0][1] == "S"


# ---------------------------------------------------------------------------
# splice_secret – error cases
# ---------------------------------------------------------------------------

def test_splice_missing_secret_raises() -> None:
    vault = _FakeVault({})
    with pytest.raises(SpliceError, match="not found"):
        splice_secret(vault, "prod", "MISSING", 0, 1, "x", _PASS)


def test_splice_invalid_range_raises() -> None:
    entry = _FakeEntry("hello")
    vault = _FakeVault({("prod", "K"): entry})
    with pytest.raises(SpliceError, match="Invalid splice range"):
        splice_secret(vault, "prod", "K", 3, 10, "x", _PASS)


def test_splice_negative_start_raises() -> None:
    entry = _FakeEntry("hello")
    vault = _FakeVault({("prod", "K"): entry})
    with pytest.raises(SpliceError, match="Invalid splice range"):
        splice_secret(vault, "prod", "K", -1, 2, "x", _PASS)
