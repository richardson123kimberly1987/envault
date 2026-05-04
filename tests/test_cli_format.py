"""Tests for envault.cli_format module."""
from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from envault.cli_format import format_group


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str) -> None:
        self._value = value

    def decrypt(self) -> str:
        return self._value

    def update_value(self, v: str) -> None:
        self._value = v

    def to_dict(self):
        return {"value": self._value}


class _FakeVault:
    def __init__(self, secrets: dict[str, str]) -> None:
        self._entries = {k: _FakeEntry(v) for k, v in secrets.items()}
        self.saved = False

    def get_secret(self, env: str, name: str):
        return self._entries.get(name)

    def list_secrets(self, env: str):
        return list(self._entries.keys())

    def save(self) -> None:
        self.saved = True


@pytest.fixture()
def runner():
    return CliRunner()


def _invoke(runner, vault, *args):
    return runner.invoke(format_group, list(args), obj={"vault": vault})


# ---------------------------------------------------------------------------
# Tests: secret subcommand
# ---------------------------------------------------------------------------

def test_secret_uppercase_success(runner):
    vault = _FakeVault({"API_KEY": "hello"})
    result = _invoke(runner, vault, "secret", "prod", "API_KEY", "--rule", "uppercase")
    assert result.exit_code == 0
    assert "HELLO" in result.output


def test_secret_json_output(runner):
    vault = _FakeVault({"TOKEN": "  value  "})
    result = _invoke(runner, vault, "secret", "dev", "TOKEN", "--rule", "strip", "--json")
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["formatted"] == "value"
    assert data["original"] == "  value  "


def test_secret_missing_exits_nonzero(runner):
    vault = _FakeVault({})
    result = _invoke(runner, vault, "secret", "prod", "MISSING", "--rule", "strip")
    assert result.exit_code != 0


def test_secret_saves_vault(runner):
    vault = _FakeVault({"K": "abc"})
    _invoke(runner, vault, "secret", "prod", "K", "--rule", "uppercase")
    assert vault.saved
    assert vault._entries["K"].decrypt() == "ABC"


def test_secret_multiple_rules(runner):
    vault = _FakeVault({"K": "  hello  "})
    result = _invoke(runner, vault, "secret", "prod", "K", "--rule", "strip", "--rule", "uppercase")
    assert result.exit_code == 0
    assert "HELLO" in result.output


# ---------------------------------------------------------------------------
# Tests: all subcommand
# ---------------------------------------------------------------------------

def test_all_formats_every_secret(runner):
    vault = _FakeVault({"A": "hello", "B": "world"})
    result = _invoke(runner, vault, "all", "prod", "--rule", "uppercase")
    assert result.exit_code == 0
    assert "HELLO" in result.output
    assert "WORLD" in result.output


def test_all_empty_environment_message(runner):
    vault = _FakeVault({})
    result = _invoke(runner, vault, "all", "prod", "--rule", "strip")
    assert result.exit_code == 0
    assert "No secrets" in result.output


def test_all_json_output(runner):
    vault = _FakeVault({"X": "abc"})
    result = _invoke(runner, vault, "all", "staging", "--rule", "lowercase", "--json")
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert isinstance(data, list)
    assert data[0]["formatted"] == "abc"
