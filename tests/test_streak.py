"""Tests for envault.streak."""
from __future__ import annotations

import json
import os
import pytest

from envault.streak import (
    STREAK_FILE,
    StreakError,
    StreakResult,
    get_streak,
    record_rotation,
    reset_streak,
)


class _FakeEntry:
    def __init__(self, value: str = "s3cr3t"):
        self._value = value

    def to_dict(self):
        return {"value": self._value}


class _FakeVault:
    def __init__(self, tmp_path, secrets=None):
        self.path = str(tmp_path / "vault.json")
        self._secrets = secrets or {}

    def get_secret(self, environment: str, secret: str):
        return self._secrets.get((environment, secret))


@pytest.fixture()
def tmp_vault(tmp_path):
    return _FakeVault(tmp_path, secrets={("prod", "DB_PASS"): _FakeEntry()})


# ---------------------------------------------------------------------------
# StreakResult.to_dict
# ---------------------------------------------------------------------------

def test_streak_result_to_dict():
    r = StreakResult(
        secret="DB_PASS",
        environment="prod",
        current_streak=3,
        longest_streak=5,
        last_rotated="2024-01-01T00:00:00+00:00",
    )
    d = r.to_dict()
    assert d["secret"] == "DB_PASS"
    assert d["environment"] == "prod"
    assert d["current_streak"] == 3
    assert d["longest_streak"] == 5
    assert d["last_rotated"] == "2024-01-01T00:00:00+00:00"


# ---------------------------------------------------------------------------
# get_streak — missing secret
# ---------------------------------------------------------------------------

def test_get_streak_missing_secret_raises(tmp_path):
    vault = _FakeVault(tmp_path, secrets={})
    with pytest.raises(StreakError, match="not found"):
        get_streak(vault, "prod", "MISSING")


# ---------------------------------------------------------------------------
# get_streak — no prior records returns zeros
# ---------------------------------------------------------------------------

def test_get_streak_no_history_returns_zeros(tmp_vault):
    result = get_streak(tmp_vault, "prod", "DB_PASS")
    assert result.current_streak == 0
    assert result.longest_streak == 0
    assert result.last_rotated is None


# ---------------------------------------------------------------------------
# record_rotation — increments streak
# ---------------------------------------------------------------------------

def test_record_rotation_increments(tmp_vault):
    r1 = record_rotation(tmp_vault, "prod", "DB_PASS")
    assert r1.current_streak == 1
    assert r1.longest_streak == 1

    r2 = record_rotation(tmp_vault, "prod", "DB_PASS")
    assert r2.current_streak == 2
    assert r2.longest_streak == 2


def test_record_rotation_persists_to_file(tmp_vault, tmp_path):
    record_rotation(tmp_vault, "prod", "DB_PASS")
    streak_path = tmp_path / STREAK_FILE
    assert streak_path.exists()
    data = json.loads(streak_path.read_text())
    assert "prod::DB_PASS" in data


def test_record_rotation_missing_secret_raises(tmp_path):
    vault = _FakeVault(tmp_path, secrets={})
    with pytest.raises(StreakError, match="not found"):
        record_rotation(vault, "prod", "MISSING")


def test_record_rotation_tracks_last_rotated(tmp_vault):
    result = record_rotation(tmp_vault, "prod", "DB_PASS")
    assert result.last_rotated is not None


# ---------------------------------------------------------------------------
# reset_streak
# ---------------------------------------------------------------------------

def test_reset_streak_zeroes_current(tmp_vault):
    record_rotation(tmp_vault, "prod", "DB_PASS")
    record_rotation(tmp_vault, "prod", "DB_PASS")
    result = reset_streak(tmp_vault, "prod", "DB_PASS")
    assert result.current_streak == 0
    assert result.longest_streak == 2  # best is preserved


def test_reset_streak_missing_secret_raises(tmp_path):
    vault = _FakeVault(tmp_path, secrets={})
    with pytest.raises(StreakError, match="not found"):
        reset_streak(vault, "prod", "MISSING")


def test_reset_then_record_restarts_from_one(tmp_vault):
    record_rotation(tmp_vault, "prod", "DB_PASS")
    record_rotation(tmp_vault, "prod", "DB_PASS")
    reset_streak(tmp_vault, "prod", "DB_PASS")
    result = record_rotation(tmp_vault, "prod", "DB_PASS")
    assert result.current_streak == 1
    assert result.longest_streak == 2
