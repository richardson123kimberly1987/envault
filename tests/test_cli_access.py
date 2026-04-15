"""Tests for envault.cli_access commands."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from envault.access import AccessPolicy
from envault.cli_access import access_group


@pytest.fixture()
def runner():
    return CliRunner()


@pytest.fixture()
def policy_file(tmp_path):
    """Patch the policy file path to a temp location."""
    policy_path = tmp_path / ".envault_access.json"
    with patch("envault.cli_access._POLICY_FILE", policy_path):
        yield policy_path


def _read_policy(policy_file: Path) -> AccessPolicy:
    return AccessPolicy.from_dict(json.loads(policy_file.read_text()))


def test_grant_creates_rule(runner, policy_file):
    result = runner.invoke(access_group, ["grant", "alice", "read"])
    assert result.exit_code == 0
    assert "Granted" in result.output
    policy = _read_policy(policy_file)
    assert policy.get_role("alice") == "read"


def test_grant_with_env_scope(runner, policy_file):
    result = runner.invoke(access_group, ["grant", "bob", "write", "--env", "production"])
    assert result.exit_code == 0
    policy = _read_policy(policy_file)
    assert policy.get_role("bob", "production") == "write"
    assert policy.get_role("bob", "staging") is None


def test_grant_replaces_existing_rule(runner, policy_file):
    runner.invoke(access_group, ["grant", "alice", "read"])
    runner.invoke(access_group, ["grant", "alice", "admin"])
    policy = _read_policy(policy_file)
    assert len(policy.rules) == 1
    assert policy.rules[0].role == "admin"


def test_revoke_removes_rule(runner, policy_file):
    runner.invoke(access_group, ["grant", "alice", "write"])
    result = runner.invoke(access_group, ["revoke", "alice"])
    assert result.exit_code == 0
    assert "Revoked" in result.output
    policy = _read_policy(policy_file)
    assert policy.get_role("alice") is None


def test_revoke_missing_identity(runner, policy_file):
    result = runner.invoke(access_group, ["revoke", "ghost"])
    assert result.exit_code == 0
    assert "No matching rule" in result.output


def test_list_shows_rules(runner, policy_file):
    runner.invoke(access_group, ["grant", "alice", "admin"])
    runner.invoke(access_group, ["grant", "bob", "read", "--env", "dev"])
    result = runner.invoke(access_group, ["list"])
    assert result.exit_code == 0
    assert "alice" in result.output
    assert "bob" in result.output


def test_list_empty_policy(runner, policy_file):
    result = runner.invoke(access_group, ["list"])
    assert result.exit_code == 0
    assert "No access rules" in result.output


def test_check_allowed(runner, policy_file):
    runner.invoke(access_group, ["grant", "alice", "admin"])
    result = runner.invoke(access_group, ["check", "alice", "write"])
    assert result.exit_code == 0
    assert "ALLOWED" in result.output


def test_check_denied(runner, policy_file):
    runner.invoke(access_group, ["grant", "bob", "read"])
    result = runner.invoke(access_group, ["check", "bob", "write"])
    assert result.exit_code == 0
    assert "DENIED" in result.output
