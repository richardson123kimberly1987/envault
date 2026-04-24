"""Tests for envault.cli_pipeline."""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from envault.cli_pipeline import pipeline_group


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str) -> None:
        self._value = value

    def to_dict(self) -> Dict[str, Any]:
        return {"value": self._value}


class _FakeVault:
    def __init__(self, secrets: Dict[str, str]) -> None:
        self._secrets = dict(secrets)
        self.saved = False

    def get_secret(self, env: str, key: str) -> Optional[_FakeEntry]:
        v = self._secrets.get(key)
        return _FakeEntry(v) if v is not None else None

    def set_secret(self, env: str, key: str, value: str) -> None:
        self._secrets[key] = value

    def list_secrets(self, env: str) -> List[str]:
        return list(self._secrets.keys())

    def save(self) -> None:
        self.saved = True


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def _invoke(runner: CliRunner, vault: _FakeVault, *args: str):
    with patch("envault.cli_pipeline._get_vault", return_value=vault):
        return runner.invoke(pipeline_group, list(args), catch_exceptions=False)


# ---------------------------------------------------------------------------
# run command
# ---------------------------------------------------------------------------

def test_run_upper_step(runner):
    vault = _FakeVault({"API_KEY": "secret"})
    result = _invoke(runner, vault, "run", "prod", "API_KEY", "--step", "upper",
                     "--vault-file", "v.json", "--passphrase", "pw")
    assert result.exit_code == 0
    assert "SECRET" in result.output
    assert vault._secrets["API_KEY"] == "SECRET"


def test_run_dry_run_does_not_mutate(runner):
    vault = _FakeVault({"KEY": "hello"})
    result = _invoke(runner, vault, "run", "prod", "KEY", "--step", "upper",
                     "--dry-run", "--vault-file", "v.json", "--passphrase", "pw")
    assert result.exit_code == 0
    assert "dry-run" in result.output
    assert vault._secrets["KEY"] == "hello"


def test_run_missing_key_shows_error(runner):
    vault = _FakeVault({})
    result = _invoke(runner, vault, "run", "prod", "MISSING", "--step", "upper",
                     "--vault-file", "v.json", "--passphrase", "pw")
    assert result.exit_code != 0
    assert "Error" in result.output


def test_run_multiple_steps(runner):
    vault = _FakeVault({"K": "  hello  "})
    result = _invoke(runner, vault, "run", "prod", "K",
                     "--step", "strip", "--step", "upper",
                     "--vault-file", "v.json", "--passphrase", "pw")
    assert result.exit_code == 0
    assert vault._secrets["K"] == "HELLO"


# ---------------------------------------------------------------------------
# run-all command
# ---------------------------------------------------------------------------

def test_run_all_processes_all_keys(runner):
    vault = _FakeVault({"A": "foo", "B": "bar"})
    result = _invoke(runner, vault, "run-all", "staging", "--step", "upper",
                     "--vault-file", "v.json", "--passphrase", "pw")
    assert result.exit_code == 0
    assert "2 secret(s)" in result.output
    assert vault._secrets["A"] == "FOO"
    assert vault._secrets["B"] == "BAR"


def test_run_all_dry_run(runner):
    vault = _FakeVault({"X": "x"})
    result = _invoke(runner, vault, "run-all", "prod", "--step", "upper",
                     "--dry-run", "--vault-file", "v.json", "--passphrase", "pw")
    assert result.exit_code == 0
    assert vault._secrets["X"] == "x"
