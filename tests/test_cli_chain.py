"""Tests for envault.cli_chain."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from envault.chain import ChainError, ChainResult
from envault.cli_chain import chain_group


@pytest.fixture()
def runner():
    return CliRunner()


def _make_result(**kwargs):
    defaults = dict(
        secret="API_KEY",
        env="dev",
        steps=["upper"],
        original="secret",
        result="SECRET",
    )
    defaults.update(kwargs)
    return ChainResult(**defaults)


def _invoke(runner, args, vault=None):
    if vault is None:
        vault = MagicMock()
    return runner.invoke(chain_group, args, obj={"vault": vault}, catch_exceptions=False)


# ---------------------------------------------------------------------------
# run command
# ---------------------------------------------------------------------------

def test_run_success_plain_output(runner):
    result = _make_result()
    with patch("envault.cli_chain.chain_secret", return_value=result):
        out = _invoke(runner, ["run", "dev", "API_KEY", "--step", "upper", "--passphrase", "p"])
    assert out.exit_code == 0
    assert "SECRET" in out.output


def test_run_success_json_output(runner):
    result = _make_result()
    with patch("envault.cli_chain.chain_secret", return_value=result):
        out = _invoke(
            runner,
            ["run", "dev", "API_KEY", "--step", "upper", "--passphrase", "p", "--json"],
        )
    assert out.exit_code == 0
    data = json.loads(out.output)
    assert data["result"] == "SECRET"


def test_run_dry_run_label(runner):
    result = _make_result()
    with patch("envault.cli_chain.chain_secret", return_value=result) as mock_fn:
        out = _invoke(
            runner,
            ["run", "dev", "API_KEY", "--step", "upper", "--passphrase", "p", "--dry-run"],
        )
    assert out.exit_code == 0
    assert "dry-run" in out.output
    _, kwargs = mock_fn.call_args
    assert kwargs.get("save") is False


def test_run_chain_error_exits_nonzero(runner):
    with patch("envault.cli_chain.chain_secret", side_effect=ChainError("bad step")):
        out = _invoke(runner, ["run", "dev", "API_KEY", "--step", "bad", "--passphrase", "p"])
    assert out.exit_code != 0
    assert "Error" in out.output


# ---------------------------------------------------------------------------
# steps command
# ---------------------------------------------------------------------------

def test_steps_lists_available_steps(runner):
    out = runner.invoke(chain_group, ["steps"], catch_exceptions=False)
    assert out.exit_code == 0
    assert "upper" in out.output
    assert "lower" in out.output
    assert "base64_encode" in out.output
