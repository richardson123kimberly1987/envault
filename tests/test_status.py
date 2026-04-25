"""Tests for envault.status."""
from __future__ import annotations

import pytest
from datetime import datetime, timedelta, timezone

from envault.status import (
    SecretStatus,
    StatusError,
    get_status,
    get_all_statuses,
)


class _FakeEntry:
    def __init__(self, data: dict):
        self._data = data

    def to_dict(self):
        return dict(self._data)


class _FakeVault:
    def __init__(self, secrets: dict):
        # secrets: {env: {key: entry_data}}
        self._secrets = secrets

    def get_secret(self, key, environment):
        env_secrets = self._secrets.get(environment, {})
        if key not in env_secrets:
            return None
        return _FakeEntry(env_secrets[key])

    def list_secrets(self, environment):
        return list(self._secrets.get(environment, {}).keys())


@pytest.fixture
def vault():
    future = (datetime.now(tz=timezone.utc) + timedelta(days=30)).isoformat()
    past = (datetime.now(tz=timezone.utc) - timedelta(days=1)).isoformat()
    return _FakeVault({
        "prod": {
            "DB_URL": {
                "locked": True,
                "pinned": False,
                "deprecated": False,
                "archived": False,
                "expiry": future,
                "ttl": 3600,
                "scopes": ["backend"],
                "tags": ["database"],
                "created_at": "2024-01-01T00:00:00",
                "updated_at": "2024-06-01T00:00:00",
            },
            "OLD_KEY": {
                "locked": False,
                "pinned": False,
                "deprecated": True,
                "archived": False,
                "expiry": past,
                "ttl": None,
                "scopes": [],
                "tags": [],
                "created_at": None,
                "updated_at": None,
            },
        }
    })


def test_get_status_returns_secret_status(vault):
    status = get_status(vault, "DB_URL", "prod")
    assert isinstance(status, SecretStatus)
    assert status.key == "DB_URL"
    assert status.environment == "prod"


def test_get_status_locked_flag(vault):
    status = get_status(vault, "DB_URL", "prod")
    assert status.locked is True


def test_get_status_deprecated_flag(vault):
    status = get_status(vault, "OLD_KEY", "prod")
    assert status.deprecated is True


def test_get_status_not_expired_for_future_expiry(vault):
    status = get_status(vault, "DB_URL", "prod")
    assert status.is_expired is False


def test_get_status_expired_for_past_expiry(vault):
    status = get_status(vault, "OLD_KEY", "prod")
    assert status.is_expired is True


def test_get_status_missing_secret_raises(vault):
    with pytest.raises(StatusError, match="MISSING"):
        get_status(vault, "MISSING", "prod")


def test_get_status_missing_env_raises(vault):
    with pytest.raises(StatusError):
        get_status(vault, "DB_URL", "staging")


def test_to_dict_contains_is_expired(vault):
    d = get_status(vault, "DB_URL", "prod").to_dict()
    assert "is_expired" in d
    assert d["is_expired"] is False


def test_to_dict_contains_all_fields(vault):
    d = get_status(vault, "DB_URL", "prod").to_dict()
    for f in ("key", "environment", "locked", "pinned", "deprecated",
               "archived", "expiry", "ttl", "scopes", "tags"):
        assert f in d


def test_get_all_statuses_returns_list(vault):
    statuses = get_all_statuses(vault, "prod")
    assert len(statuses) == 2
    keys = {s.key for s in statuses}
    assert keys == {"DB_URL", "OLD_KEY"}


def test_get_all_statuses_empty_env(vault):
    result = get_all_statuses(vault, "dev")
    assert result == []


def test_is_expired_no_expiry():
    s = SecretStatus(key="K", environment="e")
    assert s.is_expired is False


def test_is_expired_invalid_string():
    s = SecretStatus(key="K", environment="e", expiry="not-a-date")
    assert s.is_expired is False
