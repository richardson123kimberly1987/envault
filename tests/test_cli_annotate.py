"""Tests for envault.cli_annotate."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from envault.annotate import AnnotateError, AnnotateResult
from envault.cli_annotate import annotate_group


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def _invoke(runner: CliRunner, args: list[str]) -> any:
    return runner.invoke(annotate_group, args, catch_exceptions=False)


@patch("envault.cli_annotate._get_vault")
@patch(
    "envault.cli_annotate.set_annotation",
    return_value=AnnotateResult("KEY", "prod", "my note", None),
)
def test_set_new_annotation(mock_set, mock_vault, runner):
    result = _invoke(
        runner,
        ["set", "prod", "KEY", "my note", "--passphrase", "pw"],
    )
    assert result.exit_code == 0
    assert "Annotation set" in result.output
    mock_set.assert_called_once()


@patch("envault.cli_annotate._get_vault")
@patch(
    "envault.cli_annotate.set_annotation",
    return_value=AnnotateResult("KEY", "prod", "new", "old"),
)
def test_set_updates_annotation(mock_set, mock_vault, runner):
    result = _invoke(
        runner,
        ["set", "prod", "KEY", "new", "--passphrase", "pw"],
    )
    assert result.exit_code == 0
    assert "Updated" in result.output
    assert "old" in result.output


@patch("envault.cli_annotate._get_vault")
@patch(
    "envault.cli_annotate.set_annotation",
    side_effect=AnnotateError("Secret 'KEY' not found in environment 'prod'."),
)
def test_set_missing_secret_exits_nonzero(mock_set, mock_vault, runner):
    result = runner.invoke(
        annotate_group,
        ["set", "prod", "KEY", "note", "--passphrase", "pw"],
    )
    assert result.exit_code == 1
    assert "Error" in result.output


@patch("envault.cli_annotate._get_vault")
@patch(
    "envault.cli_annotate.remove_annotation",
    return_value=AnnotateResult("KEY", "prod", "", "old note"),
)
def test_remove_annotation(mock_remove, mock_vault, runner):
    result = _invoke(
        runner,
        ["remove", "prod", "KEY", "--passphrase", "pw"],
    )
    assert result.exit_code == 0
    assert "removed" in result.output
    assert "old note" in result.output


@patch("envault.cli_annotate._get_vault")
@patch(
    "envault.cli_annotate.remove_annotation",
    return_value=AnnotateResult("KEY", "prod", "", None),
)
def test_remove_annotation_none_previously(mock_remove, mock_vault, runner):
    result = _invoke(
        runner,
        ["remove", "prod", "KEY", "--passphrase", "pw"],
    )
    assert result.exit_code == 0
    assert "No annotation" in result.output


@patch("envault.cli_annotate._get_vault")
@patch(
    "envault.cli_annotate.get_annotation",
    return_value="stored note",
)
def test_get_annotation_prints_value(mock_get, mock_vault, runner):
    result = _invoke(
        runner,
        ["get", "prod", "KEY", "--passphrase", "pw"],
    )
    assert result.exit_code == 0
    assert "stored note" in result.output


@patch("envault.cli_annotate._get_vault")
@patch(
    "envault.cli_annotate.get_annotation",
    return_value=None,
)
def test_get_annotation_none(mock_get, mock_vault, runner):
    result = _invoke(
        runner,
        ["get", "prod", "KEY", "--passphrase", "pw"],
    )
    assert result.exit_code == 0
    assert "No annotation" in result.output
