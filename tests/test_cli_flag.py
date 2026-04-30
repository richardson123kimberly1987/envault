"""Tests for envault.cli_flag."""
import json
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from envault.cli_flag import flag_group


@pytest.fixture()
def runner():
    return CliRunner()


class _FakeEntry:
    def __init__(self):
        self._data = {"value": "secret", "flags": []}

    def to_dict(self):
        return dict(self._data)

    def update_value(self, value, extra=None):
        self._data["value"] = value
        if extra:
            self._data.update(extra)


class _FakeVault:
    def __init__(self):
        self._entry = _FakeEntry()
        self.saved = False

    def get_secret(self, env, key):
        if env == "prod" and key == "API_KEY":
            return self._entry
        return None

    def save(self):
        self.saved = True

    def load(self):
        pass


def _invoke(runner, args, vault):
    with patch("envault.cli_flag.Vault") as MockVault:
        instance = vault
        MockVault.return_value = instance
        return runner.invoke(
            flag_group,
            args,
            input="passphrase\n",
            catch_exceptions=False,
        )


def test_set_flag_success(runner):
    vault = _FakeVault()
    result = _invoke(runner, ["set", "prod", "API_KEY", "beta"], vault)
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "beta" in data["flags"]


def test_set_flag_missing_secret_exits_nonzero(runner):
    vault = _FakeVault()
    result = _invoke(runner, ["set", "prod", "MISSING", "beta"], vault)
    assert result.exit_code != 0


def test_unset_flag_success(runner):
    vault = _FakeVault()
    # Pre-set the flag
    vault._entry._data["flags"] = ["beta"]
    result = _invoke(runner, ["unset", "prod", "API_KEY", "beta"], vault)
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "beta" not in data["flags"]


def test_list_flags_empty(runner):
    vault = _FakeVault()
    result = _invoke(runner, ["list", "prod", "API_KEY"], vault)
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["flags"] == []


def test_list_flags_with_values(runner):
    vault = _FakeVault()
    vault._entry._data["flags"] = ["internal", "beta"]
    result = _invoke(runner, ["list", "prod", "API_KEY"], vault)
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert set(data["flags"]) == {"internal", "beta"}
