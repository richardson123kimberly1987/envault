"""Tests for envault.badge."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

import pytest

from envault.badge import (
    BADGE_COLORS,
    BADGE_STYLES,
    BadgeError,
    BadgeResult,
    generate_all_badges,
    generate_badge,
)


# ---------------------------------------------------------------------------
# Fake helpers
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, name: str, expires_at: Optional[str] = None):
        self._name = name
        self._expires_at = expires_at

    def to_dict(self) -> Dict:
        d: Dict = {"name": self._name, "value": "secret"}
        if self._expires_at:
            d["expires_at"] = self._expires_at
        return d


class _FakeVault:
    def __init__(self, data: Dict[str, Dict[str, _FakeEntry]]):
        self._data = data

    def list_environments(self) -> List[str]:
        return list(self._data.keys())

    def list_secrets(self, env: str) -> List[str]:
        return list(self._data.get(env, {}).keys())

    def get_secret(self, env: str, name: str) -> Optional[_FakeEntry]:
        return self._data.get(env, {}).get(name)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def test_badge_styles_not_empty():
    assert len(BADGE_STYLES) > 0


def test_badge_colors_has_expected_keys():
    for key in ("success", "warning", "error", "info", "unknown"):
        assert key in BADGE_COLORS


# ---------------------------------------------------------------------------
# BadgeResult.to_dict
# ---------------------------------------------------------------------------

def test_badge_result_to_dict():
    r = BadgeResult(label="prod", message="3 healthy", color="brightgreen", style="flat", url="https://example.com")
    d = r.to_dict()
    assert d["label"] == "prod"
    assert d["message"] == "3 healthy"
    assert d["color"] == "brightgreen"


# ---------------------------------------------------------------------------
# generate_badge
# ---------------------------------------------------------------------------

def test_generate_badge_no_secrets():
    vault = _FakeVault({"staging": {}})
    result = generate_badge(vault, "staging")
    assert result.message == "no secrets"
    assert result.color == BADGE_COLORS["unknown"]


def test_generate_badge_all_healthy():
    vault = _FakeVault({"prod": {"DB_PASS": _FakeEntry("DB_PASS")}})
    result = generate_badge(vault, "prod")
    assert "healthy" in result.message
    assert result.color == BADGE_COLORS["success"]


def test_generate_badge_with_expired_secret():
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    vault = _FakeVault({"prod": {"OLD": _FakeEntry("OLD", expires_at=past)}})
    result = generate_badge(vault, "prod")
    assert "expired" in result.message
    assert result.color == BADGE_COLORS["error"]


def test_generate_badge_future_expiry_is_healthy():
    future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    vault = _FakeVault({"prod": {"KEY": _FakeEntry("KEY", expires_at=future)}})
    result = generate_badge(vault, "prod")
    assert "healthy" in result.message


def test_generate_badge_invalid_style_raises():
    vault = _FakeVault({"prod": {}})
    with pytest.raises(BadgeError, match="Unknown style"):
        generate_badge(vault, "prod", style="neon")


def test_generate_badge_custom_label():
    vault = _FakeVault({"prod": {}})
    result = generate_badge(vault, "prod", label="my-app")
    assert result.label == "my-app"
    assert "my-app" in result.url


def test_generate_badge_url_format():
    vault = _FakeVault({"dev": {}})
    result = generate_badge(vault, "dev")
    assert result.url.startswith("https://img.shields.io/badge/")


# ---------------------------------------------------------------------------
# generate_all_badges
# ---------------------------------------------------------------------------

def test_generate_all_badges_returns_all_envs():
    vault = _FakeVault({
        "dev": {},
        "staging": {"X": _FakeEntry("X")},
    })
    results = generate_all_badges(vault)
    assert set(results.keys()) == {"dev", "staging"}


def test_generate_all_badges_empty_vault():
    vault = _FakeVault({})
    results = generate_all_badges(vault)
    assert results == {}
