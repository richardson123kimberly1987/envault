"""Tests for envault.cli_classify."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from envault.cli_classify import classify_group
from envault.classify import ClassifyError, ClassifyResult


@pytest.fixture()
def runner():
    return CliRunner()


def _invoke(runner, args, vault=None):
    fake_vault = vault or MagicMock()
    with patch("envault.cli_classify._get_vault", return_value=fake_vault):
        return runner.invoke(classify_group, args, catch_exceptions=False)


def test_set_classification_success(runner):
    fake_vault = MagicMock()
    result_obj = ClassifyResult(secret="API_KEY", environment="prod", level="confidential", previous="internal")
    with patch("envault.cli_classify._get_vault", return_value=fake_vault), \
         patch("envault.cli_classify.set_classification", return_value=result_obj):
        result = runner.invoke(
            classify_group,
            ["set", "prod", "API_KEY", "confidential", "--passphrase", "pw"],
            catch_exceptions=False,
        )
    assert result.exit_code == 0
    assert "confidential" in result.output
    assert "internal" in result.output


def test_set_classification_error_exits_nonzero(runner):
    fake_vault = MagicMock()
    with patch("envault.cli_classify._get_vault", return_value=fake_vault), \
         patch("envault.cli_classify.set_classification", side_effect=ClassifyError("not found")):
        result = runner.invoke(
            classify_group,
            ["set", "prod", "MISSING", "public", "--passphrase", "pw"],
        )
    assert result.exit_code != 0


def test_get_classification_plain(runner):
    fake_vault = MagicMock()
    result_obj = ClassifyResult(secret="DB", environment="dev", level="restricted")
    with patch("envault.cli_classify._get_vault", return_value=fake_vault), \
         patch("envault.cli_classify.get_classification", return_value=result_obj):
        result = runner.invoke(
            classify_group,
            ["get", "dev", "DB", "--passphrase", "pw"],
            catch_exceptions=False,
        )
    assert result.exit_code == 0
    assert "restricted" in result.output


def test_get_classification_json(runner):
    fake_vault = MagicMock()
    result_obj = ClassifyResult(secret="DB", environment="dev", level="public")
    with patch("envault.cli_classify._get_vault", return_value=fake_vault), \
         patch("envault.cli_classify.get_classification", return_value=result_obj):
        result = runner.invoke(
            classify_group,
            ["get", "dev", "DB", "--passphrase", "pw", "--json"],
            catch_exceptions=False,
        )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["level"] == "public"


def test_list_classification_plain(runner):
    fake_vault = MagicMock()
    results = [
        ClassifyResult(secret="A", environment="prod", level="confidential"),
        ClassifyResult(secret="B", environment="prod", level="confidential"),
    ]
    with patch("envault.cli_classify._get_vault", return_value=fake_vault), \
         patch("envault.cli_classify.list_by_classification", return_value=results):
        result = runner.invoke(
            classify_group,
            ["list", "prod", "confidential", "--passphrase", "pw"],
            catch_exceptions=False,
        )
    assert result.exit_code == 0
    assert "A" in result.output
    assert "B" in result.output


def test_list_classification_empty(runner):
    fake_vault = MagicMock()
    with patch("envault.cli_classify._get_vault", return_value=fake_vault), \
         patch("envault.cli_classify.list_by_classification", return_value=[]):
        result = runner.invoke(
            classify_group,
            ["list", "prod", "public", "--passphrase", "pw"],
            catch_exceptions=False,
        )
    assert result.exit_code == 0
    assert "No secrets" in result.output
