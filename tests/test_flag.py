"""Tests for envault.flag."""
import pytest
from envault.flag import (
    FLAG_KEYS,
    FlagError,
    FlagResult,
    set_flag,
    unset_flag,
    list_flags,
)


class _FakeEntry:
    def __init__(self, data: dict):
        self._data = dict(data)

    def to_dict(self) -> dict:
        return dict(self._data)

    def update_value(self, value: str, extra: dict = None):
        self._data["value"] = value
        if extra:
            self._data.update(extra)


class _FakeVault:
    def __init__(self, entries: dict):
        self._entries = entries  # {(env, key): _FakeEntry}
        self.saved = False

    def get_secret(self, environment: str, secret: str):
        return self._entries.get((environment, secret))

    def save(self):
        self.saved = True


@pytest.fixture()
def vault():
    entry = _FakeEntry({"value": "s3cr3t", "flags": []})
    return _FakeVault({("prod", "API_KEY"): entry})


def test_flag_keys_constant_not_empty():
    assert len(FLAG_KEYS) > 0


def test_flag_result_to_dict():
    r = FlagResult(secret="K", environment="e", flags=["beta"])
    d = r.to_dict()
    assert d["secret"] == "K"
    assert d["environment"] == "e"
    assert d["flags"] == ["beta"]


def test_set_flag_adds_flag(vault):
    result = set_flag(vault, "prod", "API_KEY", "beta")
    assert "beta" in result.flags
    assert vault.saved


def test_set_flag_idempotent(vault):
    set_flag(vault, "prod", "API_KEY", "beta")
    result = set_flag(vault, "prod", "API_KEY", "beta")
    assert result.flags.count("beta") == 1


def test_set_flag_unknown_raises(vault):
    with pytest.raises(FlagError, match="Unknown flag"):
        set_flag(vault, "prod", "API_KEY", "nonexistent")


def test_set_flag_missing_secret_raises():
    v = _FakeVault({})
    with pytest.raises(FlagError, match="not found"):
        set_flag(v, "prod", "MISSING", "beta")


def test_unset_flag_removes_flag(vault):
    set_flag(vault, "prod", "API_KEY", "beta")
    result = unset_flag(vault, "prod", "API_KEY", "beta")
    assert "beta" not in result.flags
    assert vault.saved


def test_unset_flag_noop_when_not_present(vault):
    result = unset_flag(vault, "prod", "API_KEY", "beta")
    assert result.flags == []


def test_list_flags_returns_current(vault):
    set_flag(vault, "prod", "API_KEY", "internal")
    result = list_flags(vault, "prod", "API_KEY")
    assert "internal" in result.flags


def test_list_flags_missing_secret_raises():
    v = _FakeVault({})
    with pytest.raises(FlagError, match="not found"):
        list_flags(v, "prod", "MISSING")
