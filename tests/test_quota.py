"""Tests for envault.quota."""
import pytest
from envault.quota import (
    DEFAULT_QUOTA,
    QuotaError,
    QuotaResult,
    check_quota,
    enforce_quota,
    set_quota,
)


class _FakeEntry:
    def __init__(self, value: str = "v"):
        self._value = value

    def to_dict(self):
        return {"value": self._value}


class _FakeVault:
    def __init__(self, secrets: dict | None = None):
        self._secrets: dict[str, dict[str, _FakeEntry]] = secrets or {}
        self.meta: dict = {}
        self._saved = False

    def list_secrets(self, environment: str):
        return list(self._secrets.get(environment, {}).keys())

    def save(self):
        self._saved = True


@pytest.fixture()
def vault():
    return _FakeVault()


def test_quota_result_to_dict():
    r = QuotaResult(environment="prod", limit=50, used=10, remaining=40, exceeded=False)
    d = r.to_dict()
    assert d["environment"] == "prod"
    assert d["limit"] == 50
    assert d["used"] == 10
    assert d["remaining"] == 40
    assert d["exceeded"] is False


def test_check_quota_uses_default(vault):
    result = check_quota(vault, "staging")
    assert result.limit == DEFAULT_QUOTA
    assert result.used == 0
    assert result.remaining == DEFAULT_QUOTA
    assert result.exceeded is False


def test_check_quota_counts_secrets(vault):
    vault._secrets["dev"] = {"A": _FakeEntry(), "B": _FakeEntry()}
    result = check_quota(vault, "dev")
    assert result.used == 2


def test_set_quota_persists(vault):
    result = set_quota(vault, "prod", 10)
    assert result.limit == 10
    assert vault._saved is True
    assert vault.meta["quotas"]["prod"] == 10


def test_set_quota_negative_raises(vault):
    with pytest.raises(QuotaError, match="non-negative"):
        set_quota(vault, "prod", -1)


def test_set_quota_zero_allowed(vault):
    result = set_quota(vault, "empty_env", 0)
    assert result.limit == 0
    assert result.exceeded is False


def test_check_quota_exceeded(vault):
    vault._secrets["prod"] = {k: _FakeEntry() for k in "ABCDE"}
    vault.meta = {"quotas": {"prod": 3}}
    result = check_quota(vault, "prod")
    assert result.exceeded is True
    assert result.remaining == 0


def test_enforce_quota_raises_when_exceeded(vault):
    vault._secrets["prod"] = {k: _FakeEntry() for k in "ABCDE"}
    vault.meta = {"quotas": {"prod": 3}}
    with pytest.raises(QuotaError, match="exceeded its quota"):
        enforce_quota(vault, "prod")


def test_enforce_quota_passes_when_within_limit(vault):
    vault._secrets["prod"] = {"A": _FakeEntry()}
    vault.meta = {"quotas": {"prod": 10}}
    enforce_quota(vault, "prod")  # should not raise


def test_set_quota_returns_remaining(vault):
    vault._secrets["qa"] = {"X": _FakeEntry(), "Y": _FakeEntry()}
    result = set_quota(vault, "qa", 5)
    assert result.remaining == 3
