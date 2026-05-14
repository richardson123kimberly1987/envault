"""Tests for envault.cli_expire_warn."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from envault.cli_expire_warn import expire_warn_group
from envault.expire_warn import ExpireWarnResult


@pytest.fixture()
def runner():
    return CliRunner()


def _future(days=30):
    return (datetime.now(tz=timezone.utc) + timedelta(days=days)).isoformat()


def _past(days=1):
    return (datetime.now(tz=timezone.utc) - timedelta(days=days)).isoformat()


def _invoke(runner, *args):
    return runner.invoke(
        expire_warn_group,
        ["--passphrase", "secret", *args],
        catch_exceptions=False,
    )


_OK_RESULT = ExpireWarnResult(
    key="API_KEY", environment="prod",
    expires_at=None, days_remaining=None,
    is_expired=False, warning=False,
)

_WARN_RESULT = ExpireWarnResult(
    key="API_KEY", environment="prod",
    expires_at=_future(3), days_remaining=3,
    is_expired=False, warning=True,
)

_EXPIRED_RESULT = ExpireWarnResult(
    key="API_KEY", environment="prod",
    expires_at=_past(2), days_remaining=-2,
    is_expired=True, warning=False,
)


def test_check_ok(runner):
    with patch("envault.cli_expire_warn._get_vault"), \
         patch("envault.cli_expire_warn.check_expiry_warning", return_value=_OK_RESULT):
        result = runner.invoke(
            expire_warn_group,
            ["check", "prod", "API_KEY", "--passphrase", "secret"],
            catch_exceptions=False,
        )
    assert result.exit_code == 0
    assert "OK" in result.output


def test_check_warning(runner):
    with patch("envault.cli_expire_warn._get_vault"), \
         patch("envault.cli_expire_warn.check_expiry_warning", return_value=_WARN_RESULT):
        result = runner.invoke(
            expire_warn_group,
            ["check", "prod", "API_KEY", "--passphrase", "secret"],
            catch_exceptions=False,
        )
    assert result.exit_code == 0
    assert "WARNING" in result.output


def test_check_expired(runner):
    with patch("envault.cli_expire_warn._get_vault"), \
         patch("envault.cli_expire_warn.check_expiry_warning", return_value=_EXPIRED_RESULT):
        result = runner.invoke(
            expire_warn_group,
            ["check", "prod", "API_KEY", "--passphrase", "secret"],
            catch_exceptions=False,
        )
    assert result.exit_code == 0
    assert "EXPIRED" in result.output


def test_check_json_output(runner):
    with patch("envault.cli_expire_warn._get_vault"), \
         patch("envault.cli_expire_warn.check_expiry_warning", return_value=_OK_RESULT):
        result = runner.invoke(
            expire_warn_group,
            ["check", "prod", "API_KEY", "--passphrase", "secret", "--json"],
            catch_exceptions=False,
        )
    assert result.exit_code == 0
    import json
    data = json.loads(result.output)
    assert data["key"] == "API_KEY"


def test_scan_no_warnings(runner):
    with patch("envault.cli_expire_warn._get_vault"), \
         patch("envault.cli_expire_warn.check_all_expiry_warnings", return_value=[]):
        result = runner.invoke(
            expire_warn_group,
            ["scan", "prod", "--passphrase", "secret"],
            catch_exceptions=False,
        )
    assert result.exit_code == 0
    assert "healthy" in result.output


def test_scan_with_warnings(runner):
    with patch("envault.cli_expire_warn._get_vault"), \
         patch("envault.cli_expire_warn.check_all_expiry_warnings", return_value=[_WARN_RESULT]):
        result = runner.invoke(
            expire_warn_group,
            ["scan", "prod", "--passphrase", "secret"],
            catch_exceptions=False,
        )
    assert result.exit_code == 0
    assert "WARNING" in result.output
