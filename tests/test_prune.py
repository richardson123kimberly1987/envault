"""Tests for envault.prune."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

import pytest

from envault.prune import PruneError, PruneResult, prune_environment


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

def _iso(dt: datetime) -> str:
    return dt.isoformat()


_FUTURE = _iso(datetime.now(timezone.utc) + timedelta(days=30))
_PAST = _iso(datetime.now(timezone.utc) - timedelta(days=1))
_STALE_DATE = _iso(datetime.now(timezone.utc) - timedelta(days=100))
_FRESH_DATE = _iso(datetime.now(timezone.utc) - timedelta(days=5))


class _FakeEntry:
    def __init__(self, expires_at: Optional[str] = None, updated_at: Optional[str] = None):
        self._data = {}
        if expires_at is not None:
            self._data["expires_at"] = expires_at
        if updated_at is not None:
            self._data["updated_at"] = updated_at

    def to_dict(self) -> dict:
        return dict(self._data)


class _FakeVault:
    def __init__(self, secrets: Dict[str, _FakeEntry]):
        self._secrets: Dict[str, _FakeEntry] = dict(secrets)
        self._deleted: List[str] = []
        self.saved = False

    def list_secrets(self, env: str) -> List[str]:
        return list(self._secrets.keys())

    def get_secret(self, env: str, name: str) -> Optional[_FakeEntry]:
        return self._secrets.get(name)

    def delete_secret(self, env: str, name: str) -> None:
        self._deleted.append(name)
        self._secrets.pop(name, None)

    def save(self) -> None:
        self.saved = True


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_prune_result_to_dict():
    r = PruneResult(environment="prod", removed=["A", "B"], dry_run=True)
    d = r.to_dict()
    assert d["environment"] == "prod"
    assert d["removed"] == ["A", "B"]
    assert d["dry_run"] is True


def test_prune_expired_removes_expired_secrets():
    vault = _FakeVault({
        "old": _FakeEntry(expires_at=_PAST),
        "valid": _FakeEntry(expires_at=_FUTURE),
    })
    result = prune_environment(vault, "prod", strategy="expired")
    assert "old" in result.removed
    assert "valid" not in result.removed
    assert vault.saved


def test_prune_stale_removes_stale_secrets():
    vault = _FakeVault({
        "stale_one": _FakeEntry(updated_at=_STALE_DATE),
        "fresh_one": _FakeEntry(updated_at=_FRESH_DATE),
    })
    result = prune_environment(vault, "dev", strategy="stale", stale_days=90)
    assert "stale_one" in result.removed
    assert "fresh_one" not in result.removed


def test_prune_all_removes_both():
    vault = _FakeVault({
        "expired_secret": _FakeEntry(expires_at=_PAST),
        "stale_secret": _FakeEntry(updated_at=_STALE_DATE),
        "good_secret": _FakeEntry(expires_at=_FUTURE, updated_at=_FRESH_DATE),
    })
    result = prune_environment(vault, "staging", strategy="all")
    assert set(result.removed) == {"expired_secret", "stale_secret"}


def test_prune_dry_run_does_not_delete():
    vault = _FakeVault({"old": _FakeEntry(expires_at=_PAST)})
    result = prune_environment(vault, "prod", strategy="expired", dry_run=True)
    assert "old" in result.removed
    assert result.dry_run is True
    assert not vault.saved
    assert "old" in vault._secrets  # not actually deleted


def test_prune_unknown_strategy_raises():
    vault = _FakeVault({})
    with pytest.raises(PruneError, match="Unknown strategy"):
        prune_environment(vault, "prod", strategy="unknown")


def test_prune_empty_vault_returns_empty_removed():
    vault = _FakeVault({})
    result = prune_environment(vault, "prod", strategy="expired")
    assert result.removed == []
    assert not vault.saved


def test_prune_no_match_does_not_save():
    vault = _FakeVault({"fresh": _FakeEntry(expires_at=_FUTURE)})
    prune_environment(vault, "prod", strategy="expired")
    assert not vault.saved
