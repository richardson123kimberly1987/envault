"""Tests for envault.score."""
from __future__ import annotations

import pytest

from envault.score import (
    SCORE_LEVELS,
    ScoreError,
    ScoreResult,
    score_all,
    score_secret,
)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str):
        self._value = value

    def to_dict(self) -> dict:
        return {"value": self._value}


class _FakeVault:
    def __init__(self, secrets: dict):
        # secrets: {env: {name: value}}
        self._secrets = secrets

    def get_secret(self, name: str, env: str):
        env_data = self._secrets.get(env, {})
        if name not in env_data:
            return None
        return _FakeEntry(env_data[name])

    def list_secrets(self, env: str):
        return list(self._secrets.get(env, {}).keys())


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_score_levels_constant_not_empty():
    assert len(SCORE_LEVELS) > 0
    assert "weak" in SCORE_LEVELS
    assert "strong" in SCORE_LEVELS


def test_score_result_to_dict():
    result = ScoreResult(
        secret_name="DB_PASS",
        environment="prod",
        score=72,
        level="strong",
        suggestions=["Add special characters."],
    )
    d = result.to_dict()
    assert d["secret_name"] == "DB_PASS"
    assert d["environment"] == "prod"
    assert d["score"] == 72
    assert d["level"] == "strong"
    assert "Add special characters." in d["suggestions"]


def test_score_missing_secret_raises():
    vault = _FakeVault({})
    with pytest.raises(ScoreError, match="not found"):
        score_secret(vault, "MISSING", "dev")


def test_score_short_secret_is_critical_or_weak():
    vault = _FakeVault({"dev": {"KEY": "abc"}})
    result = score_secret(vault, "KEY", "dev")
    assert result.level in ("critical", "weak")
    assert result.score < 45
    assert any("short" in s.lower() or "character" in s.lower() for s in result.suggestions)


def test_score_strong_secret():
    strong_value = "G7#kP!mQz2$xLv9@NrTw&Yb3^HsUo1"
    vault = _FakeVault({"prod": {"API_KEY": strong_value}})
    result = score_secret(vault, "API_KEY", "prod")
    assert result.level in ("strong", "excellent")
    assert result.score >= 65


def test_score_no_digits_suggestion():
    vault = _FakeVault({"dev": {"PW": "abcdefghijklmnopqrstuvwxyz!@#$"}})
    result = score_secret(vault, "PW", "dev")
    assert any("digit" in s.lower() for s in result.suggestions)


def test_score_no_special_chars_suggestion():
    vault = _FakeVault({"dev": {"PW": "ABCDefgh12345678ABCDefgh12345678"}})
    result = score_secret(vault, "PW", "dev")
    assert any("special" in s.lower() for s in result.suggestions)


def test_score_all_returns_list():
    vault = _FakeVault({
        "staging": {
            "DB_PASS": "short",
            "API_KEY": "V3ryStr0ng!SecretValue#2024XYZ&",
        }
    })
    results = score_all(vault, "staging")
    assert len(results) == 2
    names = {r.secret_name for r in results}
    assert "DB_PASS" in names
    assert "API_KEY" in names


def test_score_all_empty_environment():
    vault = _FakeVault({"prod": {}})
    results = score_all(vault, "prod")
    assert results == []


def test_score_result_level_in_levels():
    vault = _FakeVault({"dev": {"TOKEN": "Xy9!mKp@3Lz#QrNv&Ts2WbHu7$Eo1Ja"}})
    result = score_secret(vault, "TOKEN", "dev")
    assert result.level in SCORE_LEVELS
