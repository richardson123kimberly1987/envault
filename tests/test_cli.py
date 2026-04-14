"""Tests for envault CLI commands."""

from pathlib import Path

import pytest
from click.testing import CliRunner

from envault.cli import cli
from envault.vault import Vault

PASSPHRASE = "cli-test-passphrase"


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def vault_file(tmp_path):
    return str(tmp_path / ".envault")


def invoke(runner, vault_file, args):
    """Helper: invoke CLI with common options pre-filled."""
    return runner.invoke(
        cli,
        ["--vault", vault_file, "--passphrase", PASSPHRASE] + args,
        catch_exceptions=False,
    )


def test_set_creates_secret(runner, vault_file):
    result = invoke(runner, vault_file, ["set", "prod", "DB_HOST", "localhost"])
    assert result.exit_code == 0
    assert "DB_HOST" in result.output


def test_get_existing_secret(runner, vault_file):
    invoke(runner, vault_file, ["set", "prod", "DB_HOST", "localhost"])
    result = invoke(runner, vault_file, ["get", "prod", "DB_HOST"])
    assert result.exit_code == 0
    assert "localhost" in result.output


def test_get_missing_secret_exits_nonzero(runner, vault_file):
    result = runner.invoke(
        cli,
        ["--vault", vault_file, "--passphrase", PASSPHRASE, "get", "prod", "MISSING"],
    )
    assert result.exit_code != 0


def test_delete_secret(runner, vault_file):
    invoke(runner, vault_file, ["set", "prod", "API_KEY", "abc"])
    result = invoke(runner, vault_file, ["delete", "prod", "API_KEY"])
    assert result.exit_code == 0
    assert "Deleted" in result.output


def test_delete_missing_key_exits_nonzero(runner, vault_file):
    result = runner.invoke(
        cli,
        ["--vault", vault_file, "--passphrase", PASSPHRASE, "delete", "prod", "GHOST"],
    )
    assert result.exit_code != 0


def test_list_keys(runner, vault_file):
    invoke(runner, vault_file, ["set", "dev", "FOO", "1"])
    invoke(runner, vault_file, ["set", "dev", "BAR", "2"])
    result = invoke(runner, vault_file, ["list", "dev"])
    assert result.exit_code == 0
    assert "FOO" in result.output
    assert "BAR" in result.output


def test_list_empty_env(runner, vault_file):
    result = invoke(runner, vault_file, ["list", "empty-env"])
    assert result.exit_code == 0
    assert "No secrets" in result.output
