"""Tests for envault.cli_rename."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from envault.cli_rename import rename_group


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def runner():
    return CliRunner()


class _FakeEntry:
    def __init__(self, name: str, value: str):
        self.name = name
        self.value = value

    def to_dict(self) -> dict:
        return {"name": self.name, "value": self.value}


class _FakeVault:
    def __init__(self):
        self._data: Dict[str, Dict[str, _FakeEntry]] = {
            "prod": {"DB_PASS": _FakeEntry("DB_PASS", "secret")},
            "staging": {"DB_PASS":PASS", "dev")},
        }
        self.saved = False

    def list_environments(self) -> List[str]:
        return list(self._data.keys())

    def get_secret(self, env: str, name: str) -> Optional[_FakeEntry]:
        return self._data.get(env, {}).get(name)

    def set_secret(self, env: str, name: str, value: str) -> None:
        self._data.setdefault(env, {})[name] = _FakeEntry(name, value)

    def delete_secret(self, env: str, name: str) -> None:
        self._data.get(env, {}).pop(name, None)

    def save(self) -> None:
        self.saved = True


_fake_audit = MagicMock()


def _invoke(runner, args):
    with patch("envault.cli_rename._get_vault", return_value=_FakeVault()), \
         patch("envault.cli_rename._get_audit", return_value=_fake_audit):
        return runner.invoke(rename_group, args, catch_exceptions=False)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_secret_cmd_success(runner):
    result = _invoke(
        runner,
        ["secret", "DB_PASS", "DATABASE_PASSWORD",
         "--vault-file", "v.json", "--passphrase", "pw"],
    )
    assert result.exit_code == 0
    assert "DATABASE_PASSWORD" in result.output


def test_secret_cmd_scoped_to_env(runner):
    result = _invoke(
        runner,
        ["secret", "DB_PASS", "DATABASE_PASSWORD",
         "--vault-file", "v.json", "--passphrase", "pw", "--env", "prod"],
    )
    assert result.exit_code == 0
    assert "prod" in result.output


def test_secret_cmd_missing_key_shows_error(runner):
    with patch("envault.cli_rename._get_vault", return_value=_FakeVault()), \
         patch("envault.cli_rename._get_audit", return_value=_fake_audit):
        result = runner.invoke(
            rename_group,
            ["secret", "NONEXISTENT", "NEW",
             "--vault-file", "v.json", "--passphrase", "pw"],
            catch_exceptions=False,
        )
    assert result.exit_code != 0
    assert "Error" in result.output


def test_secret_cmd_identical_names_error(runner):
    with patch("envault.cli_rename._get_vault", return_value=_FakeVault()), \
         patch("envault.cli_rename._get_audit", return_value=_fake_audit):
        result = runner.invoke(
            rename_group,
            ["secret", "DB_PASS", "DB_PASS",
             "--vault-file", "v.json", "--passphrase", "pw"],
            catch_exceptions=False,
        )
    assert result.exit_code != 0
