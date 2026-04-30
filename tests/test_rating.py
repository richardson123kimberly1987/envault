"""Tests for envault.rating module."""
from __future__ import annotations

import pytest

from envault.rating import (
    RATING_LEVELS,
    RatingError,
    RatingResult,
    _level_for_score,
    rate_all,
    rate_secret,
)


class _FakeEntry:
    def __init__(self, value: str = "secret", tags=None, description="", expiry=None, expired=False):
        self._value = value
        self._tags = tags or []
        self._description = description
        self._expiry = expiry
        self._expired = expired

    def decrypt(self) -> str:
        return self._value

    def to_dict(self):
        return {
            "tags": self._tags,
            "description": self._description,
            "expiry": self._expiry,
            "expired": self._expired,
        }


class _FakeVault:
    def __init__(self, secrets: dict[str, _FakeEntry] | None = None):
        self._secrets = secrets or {}

    def get_secret(self, environment: str, name: str):
        return self._secrets.get(name)

    def list_secrets(self, environment: str):
        return list(self._secrets.keys())


def test_rating_levels_constant_not_empty():
    assert len(RATING_LEVELS) > 0
    assert "excellent" in RATING_LEVELS
    assert "poor" in RATING_LEVELS


def test_level_for_score_boundaries():
    assert _level_for_score(100) == "excellent"
    assert _level_for_score(90) == "excellent"
    assert _level_for_score(89) == "strong"
    assert _level_for_score(70) == "strong"
    assert _level_for_score(69) == "good"
    assert _level_for_score(50) == "good"
    assert _level_for_score(49) == "fair"
    assert _level_for_score(30) == "fair"
    assert _level_for_score(29) == "poor"
    assert _level_for_score(0) == "poor"


def test_rating_result_to_dict():
    r = RatingResult(
        secret_name="DB_PASS",
        environment="prod",
        score=75,
        level="strong",
        factors={"length": 30, "complexity": 28, "metadata": 10, "freshness": 7},
    )
    d = r.to_dict()
    assert d["secret_name"] == "DB_PASS"
    assert d["environment"] == "prod"
    assert d["score"] == 75
    assert d["level"] == "strong"
    assert "factors" in d


def test_rate_secret_missing_raises():
    vault = _FakeVault()
    with pytest.raises(RatingError, match="not found"):
        rate_secret(vault, "prod", "MISSING")


def test_rate_secret_returns_result():
    entry = _FakeEntry(value="Abc123!@#XYZ", tags=["db"], description="main db", expiry="2099-01-01")
    vault = _FakeVault({"DB_PASS": entry})
    result = rate_secret(vault, "prod", "DB_PASS")
    assert isinstance(result, RatingResult)
    assert result.secret_name == "DB_PASS"
    assert result.environment == "prod"
    assert 0 <= result.score <= 100
    assert result.level in RATING_LEVELS
    assert "length" in result.factors


def test_rate_secret_high_score_for_complex_secret():
    entry = _FakeEntry(
        value="Abc123!@#XYZabc",
        tags=["important"],
        description="very important",
        expiry="2099-01-01",
    )
    vault = _FakeVault({"KEY": entry})
    result = rate_secret(vault, "staging", "KEY")
    assert result.score >= 50


def test_rate_secret_low_score_for_short_simple():
    entry = _FakeEntry(value="ab")
    vault = _FakeVault({"KEY": entry})
    result = rate_secret(vault, "dev", "KEY")
    assert result.score < 60


def test_rate_all_returns_list():
    secrets = {
        "A": _FakeEntry(value="hello123"),
        "B": _FakeEntry(value="World!99"),
    }
    vault = _FakeVault(secrets)
    results = rate_all(vault, "dev")
    assert len(results) == 2
    names = {r.secret_name for r in results}
    assert names == {"A", "B"}


def test_rate_all_empty_vault():
    vault = _FakeVault({})
    results = rate_all(vault, "dev")
    assert results == []
