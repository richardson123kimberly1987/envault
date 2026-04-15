"""Tests for envault.cli_compare."""
from __future__ import annotations

import json
from typing import Dict, List, Optional

import pytest
from click.testing import CliRunner

from envault.cli_compare import compare_group


# ---------------------------------------------------------------------------
# Fakes & fixtures
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, encrypted_value: str):
        self.encrypted_value = encrypted_value

    def to_dict(self):
        return {"encrypted_value": self.encrypted_value}


class _FakeVault:
    def __init__(self, data):
        self._data = data

    def get_secret(self, key, env):
        return self._data.get(env, {}).get(key)

    def list_secrets(self, env):
        return list(self._data.get(env, {}).keys())


@pytest.fixture()
def runner():
    return CliRunner()


@pytest.fixture(autouse=True)
def patch_deps(monkeypatch):
    vault = _FakeVault({
        "prod": {"DB_URL": _FakeEntry("pg://prod"), "API_KEY": _FakeEntry("same")},
        "staging": {"DB_URL": _FakeEntry("pg://staging"), "API_KEY": _FakeEntry("same")},
    })
    monkeypatch.setattr("envault.cli_compare._get_vault", lambda *_a, **_kw: vault)
    monkeypatch.setattr(
        "envault.compare.decrypt",
        lambda ciphertext, passphrase: ciphertext,
    )


# ---------------------------------------------------------------------------
# secret sub-command
# ---------------------------------------------------------------------------

def test_secret_cmd_text_mismatch(runner):
    result = runner.invoke(
        compare_group,
        ["secret", "DB_URL", "--env", "prod", "--env", "staging", "--passphrase", "pw"],
    )
    assert result.exit_code == 0
    assert "mismatch" in result.output
    assert "prod" in result.output
    assert "staging" in result.output


def test_secret_cmd_text_match(runner):
    result = runner.invoke(
        compare_group,
        ["secret", "API_KEY", "--env", "prod", "--env", "staging", "--passphrase", "pw"],
    )
    assert result.exit_code == 0
    assert "match" in result.output


def test_secret_cmd_json_output(runner):
    result = runner.invoke(
        compare_group,
        ["secret", "DB_URL", "--env", "prod", "--env", "staging", "--passphrase", "pw", "--output", "json"],
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["key"] == "DB_URL"
    assert "status" in data
    assert "environments" in data


# ---------------------------------------------------------------------------
# all sub-command
# ---------------------------------------------------------------------------

def test_all_cmd_text(runner):
    result = runner.invoke(
        compare_group,
        ["all", "--env", "prod", "--env", "staging", "--passphrase", "pw"],
    )
    assert result.exit_code == 0
    assert "DB_URL" in result.output
    assert "API_KEY" in result.output


def test_all_cmd_json(runner):
    result = runner.invoke(
        compare_group,
        ["all", "--env", "prod", "--env", "staging", "--passphrase", "pw", "--output", "json"],
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert isinstance(data, list)
    assert len(data) == 2


def test_all_cmd_status_filter(runner):
    result = runner.invoke(
        compare_group,
        ["all", "--env", "prod", "--env", "staging", "--passphrase", "pw",
         "--output", "json", "--status-filter", "match"],
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert all(r["status"] == "match" for r in data)
