"""Tests for envault.cli_quota."""
import json
import pytest
from click.testing import CliRunner
from unittest.mock import MagicMock, patch

from envault.cli_quota import quota_group
from envault.quota import QuotaResult


@pytest.fixture()
def runner():
    return CliRunner()


def _invoke(runner, *args, passphrase="secret"):
    return runner.invoke(
        quota_group,
        list(args) + ["--passphrase", passphrase],
        catch_exceptions=False,
    )


def _make_result(**kwargs):
    defaults = dict(
        environment="prod",
        limit=50,
        used=5,
        remaining=45,
        exceeded=False,
    )
    defaults.update(kwargs)
    return QuotaResult(**defaults)


def test_set_quota_success(runner):
    result = _make_result(limit=20, used=3, remaining=17)
    with patch("envault.cli_quota._get_vault") as mock_vault, \
         patch("envault.cli_quota.set_quota", return_value=result) as mock_set:
        out = _invoke(runner, "set", "prod", "20")
    assert out.exit_code == 0
    assert "20" in out.output
    assert "prod" in out.output


def test_set_quota_negative_shows_error(runner):
    from envault.quota import QuotaError
    with patch("envault.cli_quota._get_vault"), \
         patch("envault.cli_quota.set_quota", side_effect=QuotaError("non-negative")):
        out = runner.invoke(
            quota_group,
            ["set", "prod", "-1", "--passphrase", "secret"],
            catch_exceptions=False,
        )
    assert out.exit_code != 0
    assert "non-negative" in out.output


def test_check_quota_ok(runner):
    result = _make_result()
    with patch("envault.cli_quota._get_vault"), \
         patch("envault.cli_quota.check_quota", return_value=result):
        out = _invoke(runner, "check", "prod")
    assert out.exit_code == 0
    assert "OK" in out.output
    assert "prod" in out.output


def test_check_quota_exceeded_exits_nonzero(runner):
    result = _make_result(limit=3, used=5, remaining=0, exceeded=True)
    with patch("envault.cli_quota._get_vault"), \
         patch("envault.cli_quota.check_quota", return_value=result):
        out = runner.invoke(
            quota_group,
            ["check", "prod", "--passphrase", "secret"],
        )
    assert out.exit_code != 0
    assert "EXCEEDED" in out.output


def test_check_quota_json_output(runner):
    result = _make_result()
    with patch("envault.cli_quota._get_vault"), \
         patch("envault.cli_quota.check_quota", return_value=result):
        out = _invoke(runner, "check", "prod", "--json")
    assert out.exit_code == 0
    data = json.loads(out.output)
    assert data["environment"] == "prod"
    assert data["limit"] == 50
    assert data["exceeded"] is False
