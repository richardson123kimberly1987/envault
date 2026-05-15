"""Tests for envault.cli_version commands."""
from __future__ import annotations

import json
from typing import Any, Dict, Optional
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from envault.cli_version import version_group


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


class _FakeVault:
    def __init__(self) -> None:
        self._store: Dict[str, Dict[str, Any]] = {
            "production": {"DB_PASS": "secret", "API_KEY": "key"}
        }
        self.saved = False

    def get_secret(self, env: str, secret: str) -> Optional[str]:
        return self._store.get(env, {}).get(secret)

    def set_secret(self, env: str, secret: str, value: Any) -> None:
        self._store.setdefault(env, {})[secret] = value

    def save(self) -> None:
        self.saved = True


def _invoke(runner: CliRunner, vault: _FakeVault, args: list) -> Any:
    with patch("envault.cli_version._get_vault", return_value=vault):
        return runner.invoke(version_group, args, catch_exceptions=False)


def test_bump_success(runner: CliRunner) -> None:
    vault = _FakeVault()
    result = _invoke(runner, vault, ["bump", "production", "DB_PASS", "--passphrase", "pw"])
    assert result.exit_code == 0
    assert "1" in result.output
    assert vault.saved


def test_bump_json_output(runner: CliRunner) -> None:
    vault = _FakeVault()
    result = _invoke(runner, vault, ["bump", "production", "DB_PASS", "--passphrase", "pw", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["version"] == 1
    assert data["secret"] == "DB_PASS"


def test_bump_missing_secret_exits_nonzero(runner: CliRunner) -> None:
    vault = _FakeVault()
    result = _invoke(runner, vault, ["bump", "production", "MISSING", "--passphrase", "pw"])
    assert result.exit_code != 0


def test_get_returns_version(runner: CliRunner) -> None:
    vault = _FakeVault()
    _invoke(runner, vault, ["bump", "production", "DB_PASS", "--passphrase", "pw"])
    result = _invoke(runner, vault, ["get", "production", "DB_PASS", "--passphrase", "pw"])
    assert result.exit_code == 0
    assert "1" in result.output


def test_get_unversioned_returns_zero(runner: CliRunner) -> None:
    vault = _FakeVault()
    result = _invoke(runner, vault, ["get", "production", "DB_PASS", "--passphrase", "pw"])
    assert result.exit_code == 0
    assert "0" in result.output


def test_list_empty(runner: CliRunner) -> None:
    vault = _FakeVault()
    result = _invoke(runner, vault, ["list", "production", "--passphrase", "pw"])
    assert result.exit_code == 0
    assert "No versioned" in result.output


def test_list_json_after_bumps(runner: CliRunner) -> None:
    vault = _FakeVault()
    _invoke(runner, vault, ["bump", "production", "DB_PASS", "--passphrase", "pw"])
    result = _invoke(runner, vault, ["list", "production", "--passphrase", "pw", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert isinstance(data, list)
    assert any(e["secret"] == "DB_PASS" for e in data)
