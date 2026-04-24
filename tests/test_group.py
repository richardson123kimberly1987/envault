"""Tests for envault.group."""

from __future__ import annotations

import json
from typing import Dict, Optional

import pytest

from envault.group import (
    GROUP_META_KEY,
    GroupError,
    GroupResult,
    add_to_group,
    list_group,
    remove_from_group,
)


# ---------------------------------------------------------------------------
# Fake helpers
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str) -> None:
        self._value = value

    def to_dict(self) -> dict:
        return {"value": self._value}


class _FakeVault:
    def __init__(self, secrets: Optional[Dict[str, Dict[str, str]]] = None) -> None:
        # {env: {key: value}}
        self._data: Dict[str, Dict[str, str]] = secrets or {}
        self.saved = False

    def get_secret(self, key: str, env: str) -> Optional[_FakeEntry]:
        val = self._data.get(env, {}).get(key)
        return _FakeEntry(val) if val is not None else None

    def set_secret(self, key: str, value: str, env: str) -> None:
        self._data.setdefault(env, {})[key] = value

    def save(self) -> None:
        self.saved = True


# ---------------------------------------------------------------------------
# GroupResult
# ---------------------------------------------------------------------------

def test_group_result_to_dict():
    r = GroupResult(group="infra", secret="DB_URL", environment="prod",
                    action="added", members=["DB_URL"])
    d = r.to_dict()
    assert d["group"] == "infra"
    assert d["action"] == "added"
    assert "DB_URL" in d["members"]


# ---------------------------------------------------------------------------
# add_to_group
# ---------------------------------------------------------------------------

def test_add_to_group_success():
    vault = _FakeVault({"prod": {"DB_URL": "postgres://localhost"}})
    result = add_to_group(vault, "infra", "DB_URL", "prod")
    assert result.action == "added"
    assert "DB_URL" in result.members
    assert vault.saved


def test_add_to_group_missing_secret_raises():
    vault = _FakeVault()
    with pytest.raises(GroupError, match="not found"):
        add_to_group(vault, "infra", "MISSING", "prod")


def test_add_to_group_idempotent():
    """Adding the same secret twice should not duplicate it."""
    vault = _FakeVault({"prod": {"DB_URL": "v"}})
    add_to_group(vault, "infra", "DB_URL", "prod")
    result = add_to_group(vault, "infra", "DB_URL", "prod")
    assert result.members.count("DB_URL") == 1


# ---------------------------------------------------------------------------
# remove_from_group
# ---------------------------------------------------------------------------

def test_remove_from_group_success():
    groups = {"infra": ["DB_URL"]}
    vault = _FakeVault({"prod": {"DB_URL": "v",
                                  GROUP_META_KEY: json.dumps(groups)}})
    result = remove_from_group(vault, "infra", "DB_URL", "prod")
    assert result.action == "removed"
    assert "DB_URL" not in result.members


def test_remove_from_group_not_member_raises():
    vault = _FakeVault({"prod": {"DB_URL": "v"}})
    with pytest.raises(GroupError, match="not a member"):
        remove_from_group(vault, "infra", "DB_URL", "prod")


# ---------------------------------------------------------------------------
# list_group
# ---------------------------------------------------------------------------

def test_list_group_returns_members():
    groups = {"infra": ["DB_URL", "REDIS_URL"]}
    vault = _FakeVault({"prod": {GROUP_META_KEY: json.dumps(groups)}})
    result = list_group(vault, "infra", "prod")
    assert result.action == "listed"
    assert set(result.members) == {"DB_URL", "REDIS_URL"}


def test_list_group_empty_when_nonexistent():
    vault = _FakeVault()
    result = list_group(vault, "ghost", "dev")
    assert result.members == []
