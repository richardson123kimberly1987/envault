"""Tests for envault.inherit."""
import pytest

from envault.inherit import InheritError, InheritResult, inherit_environment


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str):
        self.value = value

    def to_dict(self):
        return {"value": self.value}


class _FakeVault:
    def __init__(self, data: dict):
        # data = {env: {key: value_str}}
        self._data = {env: dict(secrets) for env, secrets in data.items()}
        self.saved = False

    def list_environments(self):
        return list(self._data.keys())

    def list_secrets(self, env: str):
        return list(self._data.get(env, {}).keys())

    def get_secret(self, env: str, key: str):
        secrets = self._data.get(env, {})
        if key not in secrets:
            return None
        return _FakeEntry(secrets[key])

    def set_secret(self, env: str, key: str, value: str):
        self._data.setdefault(env, {})[key] = value

    def save(self):
        self.saved = True


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_inherit_result_to_dict():
    r = InheritResult(base_env="prod", target_env="staging", inherited=["A"], skipped=["B"])
    d = r.to_dict()
    assert d["base_env"] == "prod"
    assert d["target_env"] == "staging"
    assert d["inherited"] == ["A"]
    assert d["skipped"] == ["B"]
    assert d["overwrite"] is False


def test_inherit_copies_secrets():
    vault = _FakeVault({"prod": {"DB_URL": "postgres://prod", "API_KEY": "secret"}})
    result = inherit_environment(vault, "prod", "staging")
    assert set(result.inherited) == {"DB_URL", "API_KEY"}
    assert result.skipped == []
    assert vault.get_secret("staging", "DB_URL").value == "postgres://prod"
    assert vault.saved


def test_inherit_skips_existing_without_overwrite():
    vault = _FakeVault({
        "prod": {"DB_URL": "postgres://prod", "API_KEY": "secret"},
        "staging": {"DB_URL": "postgres://staging"},
    })
    result = inherit_environment(vault, "prod", "staging", overwrite=False)
    assert "DB_URL" in result.skipped
    assert "API_KEY" in result.inherited
    # Existing value must not be overwritten
    assert vault.get_secret("staging", "DB_URL").value == "postgres://staging"


def test_inherit_overwrites_when_flag_set():
    vault = _FakeVault({
        "prod": {"DB_URL": "postgres://prod"},
        "staging": {"DB_URL": "postgres://staging"},
    })
    result = inherit_environment(vault, "prod", "staging", overwrite=True)
    assert "DB_URL" in result.inherited
    assert vault.get_secret("staging", "DB_URL").value == "postgres://prod"


def test_inherit_with_key_allowlist():
    vault = _FakeVault({"prod": {"DB_URL": "postgres://prod", "API_KEY": "secret", "EXTRA": "x"}})
    result = inherit_environment(vault, "prod", "staging", keys=["DB_URL"])
    assert result.inherited == ["DB_URL"]
    assert vault.get_secret("staging", "API_KEY") is None


def test_inherit_missing_base_env_raises():
    vault = _FakeVault({"prod": {"DB_URL": "x"}})
    with pytest.raises(InheritError, match="does not exist"):
        inherit_environment(vault, "nonexistent", "staging")


def test_inherit_same_env_raises():
    vault = _FakeVault({"prod": {"DB_URL": "x"}})
    with pytest.raises(InheritError, match="different"):
        inherit_environment(vault, "prod", "prod")


def test_inherit_missing_key_in_allowlist_raises():
    vault = _FakeVault({"prod": {"DB_URL": "x"}})
    with pytest.raises(InheritError, match="Keys not found"):
        inherit_environment(vault, "prod", "staging", keys=["MISSING_KEY"])


def test_inherit_creates_target_env_implicitly():
    vault = _FakeVault({"prod": {"TOKEN": "abc"}})
    result = inherit_environment(vault, "prod", "dev")
    assert result.inherited == ["TOKEN"]
    assert vault.get_secret("dev", "TOKEN").value == "abc"
