"""Tests for envault.promote."""
import pytest
from envault.promote import promote_environment, PromoteError, PromoteResult


class _FakeEntry:
    def __init__(self, value):
        self.value = value

    def to_dict(self):
        return {"value": self.value}


class _FakeVault:
    def __init__(self, data):
        # data: {env: {key: value}}
        self._data = {e: dict(secrets) for e, secrets in data.items()}
        self.saved = False

    def list_secrets(self, env):
        return list(self._data.get(env, {}).keys())

    def get_secret(self, env, key):
        val = self._data.get(env, {}).get(key)
        return _FakeEntry(val) if val is not None else None

    def set_secret(self, env, key, value):
        self._data.setdefault(env, {})[key] = value

    def save(self):
        self.saved = True


def test_promote_result_to_dict():
    r = PromoteResult(source="dev", destination="prod", promoted=["A"], skipped=["B"], overwritten=["C"])
    d = r.to_dict()
    assert d["source"] == "dev"
    assert d["promoted"] == ["A"]
    assert d["skipped"] == ["B"]
    assert d["overwritten"] == ["C"]


def test_promote_all_keys():
    vault = _FakeVault({"dev": {"DB": "val1", "API": "val2"}, "prod": {}})
    result = promote_environment(vault, "dev", "prod")
    assert set(result.promoted) == {"DB", "API"}
    assert result.skipped == []
    assert vault._data["prod"]["DB"] == "val1"


def test_promote_specific_keys():
    vault = _FakeVault({"dev": {"DB": "v1", "API": "v2"}, "prod": {}})
    result = promote_environment(vault, "dev", "prod", keys=["DB"])
    assert result.promoted == ["DB"]
    assert "API" not in vault._data["prod"]


def test_promote_skip_existing_without_overwrite():
    vault = _FakeVault({"dev": {"DB": "new"}, "prod": {"DB": "old"}})
    result = promote_environment(vault, "dev", "prod", overwrite=False)
    assert result.skipped == ["DB"]
    assert vault._data["prod"]["DB"] == "old"


def test_promote_overwrite_existing():
    vault = _FakeVault({"dev": {"DB": "new"}, "prod": {"DB": "old"}})
    result = promote_environment(vault, "dev", "prod", overwrite=True)
    assert result.overwritten == ["DB"]
    assert vault._data["prod"]["DB"] == "new"


def test_promote_dry_run_does_not_write():
    vault = _FakeVault({"dev": {"DB": "val"}, "prod": {}})
    result = promote_environment(vault, "dev", "prod", dry_run=True)
    assert result.promoted == ["DB"]
    assert "DB" not in vault._data.get("prod", {})


def test_promote_empty_source_raises():
    vault = _FakeVault({"dev": {}, "prod": {}})
    with pytest.raises(PromoteError, match="no secrets"):
        promote_environment(vault, "dev", "prod")


def test_promote_unknown_key_raises():
    vault = _FakeVault({"dev": {"DB": "v"}, "prod": {}})
    with pytest.raises(PromoteError, match="not found in source"):
        promote_environment(vault, "dev", "prod", keys=["MISSING"])
