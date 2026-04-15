"""Tests for envault.rotation."""

from __future__ import annotations

import pytest

from envault.rotation import RotationError, rotate_all, rotate_secret


class _FakeEntry:
    """Minimal stand-in for SecretEntry."""

    def __init__(self, value: str):
        self.value = value

    def to_dict(self):
        return {"value": self.value}


class _FakeVault:
    """Minimal in-memory vault for testing rotation logic."""

    def __init__(self, initial: dict | None = None):
        self._store: dict[tuple, str] = {}
        for (k, env), v in (initial or {}).items():
            self._store[(k, env)] = v

    def get(self, key: str, environment: str = "default"):
        val = self._store.get((key, environment))
        if val is None:
            return None
        return _FakeEntry(val)

    def set(self, key: str, value: str, environment: str = "default"):
        self._store[(key, environment)] = value


# ---------------------------------------------------------------------------
# rotate_secret
# ---------------------------------------------------------------------------

def test_rotate_secret_updates_value():
    vault = _FakeVault({("DB_PASS", "default"): "old"})
    rotate_secret(vault, "DB_PASS", "new")
    assert vault.get("DB_PASS").value == "new"


def test_rotate_secret_returns_metadata():
    vault = _FakeVault({("API_KEY", "prod"): "v1"})
    result = rotate_secret(vault, "API_KEY", "v2", environment="prod")
    assert result["key"] == "API_KEY"
    assert result["environment"] == "prod"
    assert "rotated_at" in result
    assert result["rotated_at"].endswith("Z")


def test_rotate_secret_preserves_previous_version():
    vault = _FakeVault({("TOKEN", "default"): "original"})
    result = rotate_secret(vault, "TOKEN", "updated")
    assert result["previous_version"]["value"] == "original"


def test_rotate_secret_missing_key_raises():
    vault = _FakeVault()
    with pytest.raises(RotationError, match="not found"):
        rotate_secret(vault, "MISSING", "value")


# ---------------------------------------------------------------------------
# rotate_all
# ---------------------------------------------------------------------------

def test_rotate_all_rotates_existing_keys():
    vault = _FakeVault({("A", "default"): "a1", ("B", "default"): "b1"})
    results = rotate_all(vault, {"A": "a2", "B": "b2"})
    assert all(not r["skipped"] for r in results)
    assert vault.get("A").value == "a2"
    assert vault.get("B").value == "b2"


def test_rotate_all_skips_missing_keys():
    vault = _FakeVault({("EXISTS", "default"): "val"})
    results = rotate_all(vault, {"EXISTS": "new", "GHOST": "x"})
    skipped = [r for r in results if r["skipped"]]
    assert len(skipped) == 1
    assert skipped[0]["key"] == "GHOST"


def test_rotate_all_empty_updates():
    vault = _FakeVault()
    results = rotate_all(vault, {})
    assert results == []
