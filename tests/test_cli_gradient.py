"""Tests for envault.cli_gradient."""
from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from envault.cli_gradient import gradient_group
from envault.gradient import GradientResult


class _FakeEntry:
    def __init__(self, **kwargs):
        self._data = kwargs

    def to_dict(self):
        return dict(self._data)


class _FakeVault:
    def __init__(self, secrets):
        self._secrets = secrets

    def get_secret(self, env, name):
        return self._secrets.get(env, {}).get(name)

    def list_secrets(self, env):
        return list(self._secrets.get(env, {}).keys())


@pytest.fixture()
def runner():
    return CliRunner()


_ENTRY = _FakeEntry(
    classification="secret",
    scopes=["prod"],
    expires_at=None,
    tags=["pii"],
    locked=False,
    priority="high",
)


def _invoke(runner, args, vault=None):
    if vault is None:
        vault = _FakeVault({"prod": {"DB_PASS": _ENTRY}})
    return runner.invoke(gradient_group, args, obj={"vault": vault})


def test_score_plain_output(runner):
    result = _invoke(runner, ["score", "prod", "DB_PASS"])
    assert result.exit_code == 0
    assert "DB_PASS" in result.output
    assert "Score" in result.output
    assert "Level" in result.output


def test_score_json_output(runner):
    result = _invoke(runner, ["score", "prod", "DB_PASS", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["secret"] == "DB_PASS"
    assert "score" in data
    assert "level" in data
    assert "dimensions" in data


def test_score_missing_secret_exits_nonzero(runner):
    vault = _FakeVault({"prod": {}})
    result = _invoke(runner, ["score", "prod", "MISSING"], vault=vault)
    assert result.exit_code != 0
    assert "Error" in result.output


def test_all_plain_output(runner):
    vault = _FakeVault({"prod": {"DB_PASS": _ENTRY}})
    result = runner.invoke(gradient_group, ["all", "prod"], obj={"vault": vault})
    assert result.exit_code == 0
    assert "DB_PASS" in result.output


def test_all_json_output(runner):
    vault = _FakeVault({"prod": {"DB_PASS": _ENTRY}})
    result = runner.invoke(
        gradient_group, ["all", "prod", "--json"], obj={"vault": vault}
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert isinstance(data, list)
    assert data[0]["secret"] == "DB_PASS"


def test_all_empty_environment(runner):
    vault = _FakeVault({"prod": {}})
    result = runner.invoke(gradient_group, ["all", "prod"], obj={"vault": vault})
    assert result.exit_code == 0
    assert "No secrets found" in result.output


def test_all_min_level_filters(runner):
    low_entry = _FakeEntry(
        classification="public", scopes=[],
        expires_at="2099-01-01", tags=[],
        locked=True, priority="low"
    )
    high_entry = _FakeEntry(
        classification="secret", scopes=["a", "b", "c"],
        expires_at=None, tags=["pii", "credential"],
        locked=False, priority="critical"
    )
    vault = _FakeVault({"prod": {"LOW": low_entry, "HIGH": high_entry}})
    result = runner.invoke(
        gradient_group, ["all", "prod", "--min-level", "high", "--json"],
        obj={"vault": vault}
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    names = [r["secret"] for r in data]
    assert "HIGH" in names
    assert "LOW" not in names
