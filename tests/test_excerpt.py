"""Tests for envault.excerpt."""
from __future__ import annotations

import pytest

from envault.excerpt import ExcerptError, ExcerptResult, excerpt_secret


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str):
        self._value = value

    def decrypt(self) -> str:
        return self._value

    def to_dict(self):
        return {"value": self._value}


class _FakeVault:
    def __init__(self, secrets: dict):
        # secrets: {(env, name): value}
        self._secrets = secrets

    def get_secret(self, environment: str, secret: str):
        key = (environment, secret)
        if key not in self._secrets:
            return None
        return _FakeEntry(self._secrets[key])


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_excerpt_result_to_dict():
    r = ExcerptResult(
        secret="KEY",
        environment="prod",
        original_length=10,
        excerpt="hel",
        start=0,
        end=3,
    )
    d = r.to_dict()
    assert d["secret"] == "KEY"
    assert d["excerpt"] == "hel"
    assert d["original_length"] == 10


def test_excerpt_full_value():
    vault = _FakeVault({("dev", "TOKEN"): "abcdefgh"})
    result = excerpt_secret(vault, "dev", "TOKEN")
    assert result.excerpt == "abcdefgh"
    assert result.start == 0
    assert result.end == 8


def test_excerpt_with_start_and_end():
    vault = _FakeVault({("dev", "TOKEN"): "abcdefgh"})
    result = excerpt_secret(vault, "dev", "TOKEN", start=2, end=5)
    assert result.excerpt == "cde"
    assert result.start == 2
    assert result.end == 5


def test_excerpt_start_only():
    vault = _FakeVault({("dev", "TOKEN"): "hello world"})
    result = excerpt_secret(vault, "dev", "TOKEN", start=6)
    assert result.excerpt == "world"


def test_excerpt_end_beyond_length_clamps():
    vault = _FakeVault({("dev", "TOKEN"): "short"})
    result = excerpt_secret(vault, "dev", "TOKEN", start=0, end=100)
    assert result.excerpt == "short"
    assert result.end == 5


def test_excerpt_missing_secret_raises():
    vault = _FakeVault({})
    with pytest.raises(ExcerptError, match="not found"):
        excerpt_secret(vault, "dev", "MISSING")


def test_excerpt_negative_start_raises():
    vault = _FakeVault({("dev", "TOKEN"): "value"})
    with pytest.raises(ExcerptError, match="non-negative"):
        excerpt_secret(vault, "dev", "TOKEN", start=-1)


def test_excerpt_end_less_than_start_raises():
    vault = _FakeVault({("dev", "TOKEN"): "value"})
    with pytest.raises(ExcerptError, match="greater than or equal"):
        excerpt_secret(vault, "dev", "TOKEN", start=4, end=2)
