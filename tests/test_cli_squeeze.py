"""Tests for envault.cli_squeeze."""
from __future__ import annotations

import json
from typing import Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from envault.cli_squeeze import squeeze_group
from envault.squeeze import SqueezeResult


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def _invoke(runner: CliRunner, args, *, result: SqueezeResult):
    """Invoke the squeeze run command with a mocked squeeze_environment."""
    with patch("envault.cli_squeeze.Vault") as MockVault, \
         patch("envault.cli_squeeze.squeeze_environment", return_value=result):
        mock_vault_instance = MagicMock()
        MockVault.return_value = mock_vault_instance
        return runner.invoke(
            squeeze_group,
            ["run"] + args + ["--passphrase", "secret"],
            catch_exceptions=False,
        )


def test_run_reports_removed(runner, tmp_path):
    vf = tmp_path / "vault.json"
    vf.write_text("{}")
    result = SqueezeResult(environment="dev", removed=["BLANK", "EMPTY"], kept=2)
    out = _invoke(runner, [str(vf), "dev"], result=result)
    assert out.exit_code == 0
    assert "BLANK" in out.output
    assert "EMPTY" in out.output
    assert "Kept: 2" in out.output


def test_run_no_blanks_message(runner, tmp_path):
    vf = tmp_path / "vault.json"
    vf.write_text("{}")
    result = SqueezeResult(environment="prod", removed=[], kept=5)
    out = _invoke(runner, [str(vf), "prod"], result=result)
    assert out.exit_code == 0
    assert "No blank secrets" in out.output


def test_run_dry_run_label(runner, tmp_path):
    vf = tmp_path / "vault.json"
    vf.write_text("{}")
    result = SqueezeResult(environment="qa", removed=["X"], kept=1, dry_run=True)
    out = _invoke(runner, [str(vf), "qa", "--dry-run"], result=result)
    assert out.exit_code == 0
    assert "[dry-run]" in out.output


def test_run_json_output(runner, tmp_path):
    vf = tmp_path / "vault.json"
    vf.write_text("{}")
    result = SqueezeResult(environment="dev", removed=["A"], kept=3)
    out = _invoke(runner, [str(vf), "dev", "--json"], result=result)
    assert out.exit_code == 0
    data = json.loads(out.output)
    assert data["environment"] == "dev"
    assert data["removed"] == ["A"]
    assert data["kept"] == 3


def test_run_error_exits_nonzero(runner, tmp_path):
    vf = tmp_path / "vault.json"
    vf.write_text("{}")
    from envault.squeeze import SqueezeError
    with patch("envault.cli_squeeze.Vault") as MockVault, \
         patch("envault.cli_squeeze.squeeze_environment", side_effect=SqueezeError("boom")):
        MockVault.return_value = MagicMock()
        out = runner.invoke(
            squeeze_group,
            ["run", str(vf), "dev", "--passphrase", "secret"],
            catch_exceptions=False,
        )
    assert out.exit_code != 0
    assert "boom" in out.output
