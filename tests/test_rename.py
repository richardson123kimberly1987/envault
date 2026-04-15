"""Tests for envault.rename."""
from __future__ import annotations

from typing import Dict, List, Optional

import pytest

from envault.rename import RenameError, RenameResult, rename_secret


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, name: str, value: str):
        self.name = name
        self.value = value

    def to_dict(self) -> dict:
        return {"name": self.name, "value": self.value}


class _FakeVault:
    def __init__(self, data: Dict[str, Dict[str, _FakeEntry]]):
        # data = {env: {key: entry}}
        self._data: Dict[str, Dict[str, _FakeEntry]] = {
            env: dict(secrets) for env, secrets in data.items()
        }

    def list_environments(self) -> List[str]:
        return list(self._data.keys())

    def get_secret(self, env: str, name: str) -> Optional[_FakeEntry]:
        return self._data.get(env, {}).get(name)

    def set_secret(self, env: str, name: str, value: str) -> None:
        if env not in self._data:
            self._data[env] = {}
        self._data[env][name] = _FakeEntry(name, value)

    def delete_secret(self, env: str, name: str) -> None:
        self._data.get(env, {}).pop(name, None)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _vault_with(envs: Dict[str, Dict[str, str]]) -> _FakeVault:
    return _FakeVault(
        {env: {k: _FakeEntry(k, v) for k, v in secrets.items()}
         for env, secrets in envs.items()}
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_rename_result_to_dict():
    r = RenameResult("OLD", "NEW", ["prod"], ["staging"])
    d = r.to_dict()
    assert d["old_name"] == "OLD"
    assert d["new_name"] == "NEW"
    assert d["environments_updated"] == ["prod"]
    assert d["skipped_environments"] == ["staging"]


def test_rename_across_all_environments():
    vault = _vault_with({"prod": {"DB_PASS": "s3cr3t"}, "staging": {"DB_PASS": "dev"}})
    result = rename_secret(vault, "DB_PASS", "DATABASE_PASSWORD")
    assert set(result.environments_updated) == {"prod", "staging"}
    assert result.skipped_environments == []
    assert vault.get_secret("prod", "DB_PASS") is None
    assert vault.get_secret("prod", "DATABASE_PASSWORD") is not None


def test_rename_scoped_to_single_env():
    vault = _vault_with({"prod": {"API_KEY": "abc"}, "staging": {"API_KEY": "xyz"}})
    result = rename_secret(vault, "API_KEY", "API_TOKEN", env="prod")
    assert result.environments_updated == ["prod"]
    # staging untouched
    assert vault.get_secret("staging", "API_KEY") is not None
    assert vault.get_secret("staging", "API_TOKEN") is None


def test_rename_skips_envs_without_key():
    vault = _vault_with({"prod": {"SECRET": "val"}, "staging": {}})
    result = rename_secret(vault, "SECRET", "SECRET_KEY")
    assert "prod" in result.environments_updated
    assert "staging" in result.skipped_environments


def test_rename_raises_when_key_not_found_anywhere():
    vault = _vault_with({"prod": {}, "staging": {}})
    with pytest.raises(RenameError, match="not found"):
        rename_secret(vault, "MISSING", "NEW_NAME")


def test_rename_raises_when_new_name_exists():
    vault = _vault_with({"prod": {"OLD": "v", "NEW": "existing"}})
    with pytest.raises(RenameError, match="already exists"):
        rename_secret(vault, "OLD", "NEW")


def test_rename_raises_on_empty_old_name():
    vault = _vault_with({"prod": {"X": "v"}})
    with pytest.raises(RenameError, match="empty"):
        rename_secret(vault, "", "Y")


def test_rename_raises_on_empty_new_name():
    vault = _vault_with({"prod": {"X": "v"}})
    with pytest.raises(RenameError, match="empty"):
        rename_secret(vault, "X", "")


def test_rename_raises_when_names_identical():
    vault = _vault_with({"prod": {"X": "v"}})
    with pytest.raises(RenameError, match="identical"):
        rename_secret(vault, "X", "X")
