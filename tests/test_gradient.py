"""Tests for envault.gradient."""
from __future__ import annotations

import pytest

from envault.gradient import (
    GRADIENT_LEVELS,
    GradientError,
    GradientResult,
    _level_for_score,
    compute_gradient,
    compute_gradient_all,
)


class _FakeEntry:
    def __init__(self, **kwargs):
        self._data = kwargs

    def to_dict(self):
        return dict(self._data)


class _FakeVault:
    def __init__(self, secrets):
        # secrets: {env: {name: _FakeEntry}}
        self._secrets = secrets

    def get_secret(self, env, name):
        return self._secrets.get(env, {}).get(name)

    def list_secrets(self, env):
        return list(self._secrets.get(env, {}).keys())


# ---------------------------------------------------------------------------
# Unit tests for helpers
# ---------------------------------------------------------------------------

def test_gradient_levels_constant_not_empty():
    assert len(GRADIENT_LEVELS) > 0


@pytest.mark.parametrize("score,expected", [
    (0.0, "negligible"),
    (0.19, "negligible"),
    (0.2, "low"),
    (0.39, "low"),
    (0.4, "medium"),
    (0.59, "medium"),
    (0.6, "high"),
    (0.79, "high"),
    (0.8, "critical"),
    (1.0, "critical"),
])
def test_level_for_score(score, expected):
    assert _level_for_score(score) == expected


def test_gradient_result_to_dict():
    r = GradientResult(
        secret="DB_PASS",
        environment="prod",
        score=0.75,
        level="high",
        dimensions={"classification": 1.0},
    )
    d = r.to_dict()
    assert d["secret"] == "DB_PASS"
    assert d["environment"] == "prod"
    assert d["level"] == "high"
    assert isinstance(d["score"], float)
    assert "classification" in d["dimensions"]


# ---------------------------------------------------------------------------
# compute_gradient
# ---------------------------------------------------------------------------

def test_compute_gradient_missing_secret_raises():
    vault = _FakeVault({})
    with pytest.raises(GradientError):
        compute_gradient(vault, "prod", "MISSING")


def test_compute_gradient_returns_gradient_result():
    entry = _FakeEntry(
        classification="secret",
        scopes=["prod", "staging"],
        expires_at=None,
        tags=["credential", "pii"],
        locked=False,
        priority="high",
    )
    vault = _FakeVault({"prod": {"API_KEY": entry}})
    result = compute_gradient(vault, "prod", "API_KEY")
    assert isinstance(result, GradientResult)
    assert 0.0 <= result.score <= 1.0
    assert result.level in GRADIENT_LEVELS
    assert result.secret == "API_KEY"
    assert result.environment == "prod"


def test_compute_gradient_locked_with_expiry_lower_score():
    """A locked secret with expiry should score lower than an unlocked one without."""
    risky = _FakeEntry(
        classification="secret", scopes=[], expires_at=None,
        tags=[], locked=False, priority="high"
    )
    safe = _FakeEntry(
        classification="public", scopes=[], expires_at="2099-01-01T00:00:00",
        tags=[], locked=True, priority="low"
    )
    vault = _FakeVault({"prod": {"RISKY": risky, "SAFE": safe}})
    r_risky = compute_gradient(vault, "prod", "RISKY")
    r_safe = compute_gradient(vault, "prod", "SAFE")
    assert r_risky.score > r_safe.score


def test_compute_gradient_dimensions_keys():
    entry = _FakeEntry(
        classification="internal", scopes=[],
        expires_at="2030-01-01", tags=[], locked=True, priority="medium"
    )
    vault = _FakeVault({"dev": {"TOKEN": entry}})
    result = compute_gradient(vault, "dev", "TOKEN")
    expected_keys = {"classification", "scope", "expiry", "tags", "lock", "priority"}
    assert expected_keys == set(result.dimensions.keys())


# ---------------------------------------------------------------------------
# compute_gradient_all
# ---------------------------------------------------------------------------

def test_compute_gradient_all_returns_sorted_descending():
    entries = {
        "A": _FakeEntry(
            classification="secret", scopes=["a", "b", "c"],
            expires_at=None, tags=["pii", "credential"],
            locked=False, priority="critical"
        ),
        "B": _FakeEntry(
            classification="public", scopes=[],
            expires_at="2099-01-01", tags=[],
            locked=True, priority="low"
        ),
    }
    vault = _FakeVault({"prod": entries})
    results = compute_gradient_all(vault, "prod")
    assert len(results) == 2
    assert results[0].score >= results[1].score


def test_compute_gradient_all_empty_environment():
    vault = _FakeVault({"prod": {}})
    results = compute_gradient_all(vault, "prod")
    assert results == []
