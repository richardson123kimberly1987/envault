"""Tests for envault.cli_expiry."""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from envault.cli_expiry import expiry_group
from envault.expiry import EXPIRY_DATE_FORMAT, ExpiryResult


@pytest.fixture
def runner():
    return CliRunner()


def _future(days=10):
    return (datetime.now(timezone.utc) + timedelta(days=days)).strftime(EXPIRY_DATE_FORMAT)


def _past(days=1):
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime(EXPIRY_DATE_FORMAT)


# ---------------------------------------------------------------------------
# set command
# ---------------------------------------------------------------------------

def test_set_with_days(runner):
    mock_vault = MagicMock()
    mock_result = ExpiryResult("prod", "KEY", _future(7), False, 7)
    with patch("envault.cli_expiry._get_vault", return_value=mock_vault), \
         patch("envault.cli_expiry.set_expiry", return_value=mock_result) as mock_set:
        result = runner.invoke(expiry_group, [
            "set", "--vault", "v.enc", "--passphrase", "pass",
            "--env", "prod", "--key", "KEY", "--days", "7",
        ])
    assert result.exit_code == 0
    assert "expires at" in result.output
    mock_vault.save.assert_called_once()


def test_set_with_explicit_date(runner):
    mock_vault = MagicMock()
    date = _future(20)
    mock_result = ExpiryResult("prod", "KEY", date, False, 20)
    with patch("envault.cli_expiry._get_vault", return_value=mock_vault), \
         patch("envault.cli_expiry.set_expiry", return_value=mock_result):
        result = runner.invoke(expiry_group, [
            "set", "--vault", "v.enc", "--passphrase", "pass",
            "--env", "prod", "--key", "KEY", "--date", date,
        ])
    assert result.exit_code == 0


def test_set_no_date_or_days_fails(runner):
    result = runner.invoke(expiry_group, [
        "set", "--vault", "v.enc", "--passphrase", "pass",
        "--env", "prod", "--key", "KEY",
    ])
    assert result.exit_code != 0


def test_set_expiry_error_shown(runner):
    from envault.expiry import ExpiryError
    mock_vault = MagicMock()
    with patch("envault.cli_expiry._get_vault", return_value=mock_vault), \
         patch("envault.cli_expiry.set_expiry", side_effect=ExpiryError("not found")):
        result = runner.invoke(expiry_group, [
            "set", "--vault", "v.enc", "--passphrase", "pass",
            "--env", "prod", "--key", "GHOST", "--days", "5",
        ])
    assert result.exit_code != 0
    assert "not found" in result.output


# ---------------------------------------------------------------------------
# check command
# ---------------------------------------------------------------------------

def test_check_no_expiry(runner):
    mock_vault = MagicMock()
    mock_result = ExpiryResult("prod", "KEY", None, False, None)
    with patch("envault.cli_expiry._get_vault", return_value=mock_vault), \
         patch("envault.cli_expiry.check_expiry", return_value=mock_result):
        result = runner.invoke(expiry_group, [
            "check", "--vault", "v.enc", "--passphrase", "pass",
            "--env", "prod", "--key", "KEY",
        ])
    assert result.exit_code == 0
    assert "no expiry" in result.output


def test_check_expired(runner):
    mock_vault = MagicMock()
    mock_result = ExpiryResult("prod", "KEY", _past(), True, None)
    with patch("envault.cli_expiry._get_vault", return_value=mock_vault), \
         patch("envault.cli_expiry.check_expiry", return_value=mock_result):
        result = runner.invoke(expiry_group, [
            "check", "--vault", "v.enc", "--passphrase", "pass",
            "--env", "prod", "--key", "KEY",
        ])
    assert result.exit_code == 0
    assert "EXPIRED" in result.output


def test_check_future(runner):
    mock_vault = MagicMock()
    mock_result = ExpiryResult("prod", "KEY", _future(5), False, 5)
    with patch("envault.cli_expiry._get_vault", return_value=mock_vault), \
         patch("envault.cli_expiry.check_expiry", return_value=mock_result):
        result = runner.invoke(expiry_group, [
            "check", "--vault", "v.enc", "--passphrase", "pass",
            "--env", "prod", "--key", "KEY",
        ])
    assert result.exit_code == 0
    assert "5 days remaining" in result.output


# ---------------------------------------------------------------------------
# list command
# ---------------------------------------------------------------------------

def test_list_no_expiring(runner):
    mock_vault = MagicMock()
    with patch("envault.cli_expiry._get_vault", return_value=mock_vault), \
         patch("envault.cli_expiry.list_expiring", return_value=[]):
        result = runner.invoke(expiry_group, [
            "list", "--vault", "v.enc", "--passphrase", "pass", "--env", "prod",
        ])
    assert result.exit_code == 0
    assert "No secrets expiring" in result.output


def test_list_shows_results(runner):
    mock_vault = MagicMock()
    items = [
        ExpiryResult("prod", "A", _future(3), False, 3),
        ExpiryResult("prod", "B", _past(), True, None),
    ]
    with patch("envault.cli_expiry._get_vault", return_value=mock_vault), \
         patch("envault.cli_expiry.list_expiring", return_value=items):
        result = runner.invoke(expiry_group, [
            "list", "--vault", "v.enc", "--passphrase", "pass", "--env", "prod",
        ])
    assert result.exit_code == 0
    assert "A" in result.output
    assert "B" in result.output
    assert "EXPIRED" in result.output
