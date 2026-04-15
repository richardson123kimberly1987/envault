"""Tests for envault.clone."""

from __future__ import annotations

from typing import Dict, List, Optional

import pytest

from envault.clone import CloneError, CloneResult, clone_environment


class _FakeEntry:
    def __init__(self, value: str):
        self.value = value

    def to_dict(self):
        return {"value": self.value}


class _FakeVault:
    def __init__(self, data: Dict[str, Dict[str, str]]):
        # data: {env: {key: value}}
        self._data: Dict[str, Dict[str, _FakeEntry]] = {
            env: {k: _FakeEntry(v) for k, v in secrets.items()}
            for env, secrets in data.items()
        }

    def list_environments(self) -> List[str]:
        return list(self._data.keys())

    def list_secrets(self, env: str) -> List[str]:
        return list(self._data.get(env, {}).keys())

    def get_secret(self, env: str, key: str) -> Optional[_FakeEntry]:
        return self._data.get(env, {}).get(key)

    def set_secret(self, env: str, key: str, value: str) -> None:
        if env not in self._data:
            self._data[env] = {}
        self._data[env][key] = _FakeEntry(value)


@pytest.fixture
def vault():
    return _FakeVault(
        {
            "prod": {"DB_URL": "postgres://prod", "API_KEY": "abc123"},
            "staging": {"DB_URL": "postgres://staging"},
        }
    )


def test_clone_result_to_dict():
    result = CloneResult(
        source_env="prod",
        target_env="dev",
        cloned=["DB_URL"],
        skipped=["API_KEY"],
    )
    d = result.to_dict()
    assert d["source_env"] == "prod"
    assert d["target_env"] == "dev"
    assert d["cloned"] == ["DB_URL"]
    assert d["skipped"] == ["API_KEY"]


def test_clone_all_secrets_to_new_env(vault):
    result = clone_environment(vault, "prod", "dev")
    assert set(result.cloned) == {"DB_URL", "API_KEY"}
    assert result.skipped == []
    assert vault.get_secret("dev", "DB_URL").value == "postgres://prod"
    assert vault.get_secret("dev", "API_KEY").value == "abc123"


def test_clone_skips_existing_without_overwrite(vault):
    result = clone_environment(vault, "prod", "staging")
    assert "DB_URL" in result.skipped
    assert "API_KEY" in result.cloned
    # Original staging value preserved
    assert vault.get_secret("staging", "DB_URL").value == "postgres://staging"


def test_clone_overwrites_when_flag_set(vault):
    result = clone_environment(vault, "prod", "staging", overwrite=True)
    assert "DB_URL" in result.cloned
    assert vault.get_secret("staging", "DB_URL").value == "postgres://prod"


def test_clone_specific_keys(vault):
    result = clone_environment(vault, "prod", "dev", keys=["API_KEY"])
    assert result.cloned == ["API_KEY"]
    assert vault.get_secret("dev", "API_KEY").value == "abc123"
    assert vault.get_secret("dev", "DB_URL") is None


def test_clone_same_env_raises(vault):
    with pytest.raises(CloneError, match="must differ"):
        clone_environment(vault, "prod", "prod")


def test_clone_missing_source_raises(vault):
    with pytest.raises(CloneError, match="does not exist"):
        clone_environment(vault, "nonexistent", "dev")


def test_clone_missing_keys_raises(vault):
    with pytest.raises(CloneError, match="Keys not found"):
        clone_environment(vault, "prod", "dev", keys=["MISSING_KEY"])
