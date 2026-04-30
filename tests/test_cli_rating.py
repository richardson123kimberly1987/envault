"""Tests for envault.cli_rating commands."""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from envault.cli_rating import rating_group
from envault.rating import RatingError, RatingResult


@pytest.fixture()
def runner():
    return CliRunner()


def _invoke(runner, *args):
    return runner.invoke(
        rating_group,
        ["--vault-file", "v.json", "--passphrase", "pw", *args],
        catch_exceptions=False,
    )


_GOOD_RESULT = RatingResult(
    secret_name="API_KEY",
    environment="prod",
    score=85,
    level="strong",
    factors={"length": 30, "complexity": 28, "metadata": 10, "freshness": 17},
)


def test_score_success(runner):
    with (
        patch("envault.cli_rating._get_vault"),
        patch("envault.cli_rating.rate_secret", return_value=_GOOD_RESULT),
    ):
        result = runner.invoke(
            rating_group,
            ["score", "prod", "API_KEY", "--vault-file", "v.json", "--passphrase", "pw"],
            catch_exceptions=False,
        )
    assert result.exit_code == 0
    assert "85/100" in result.output
    assert "strong" in result.output


def test_score_json_output(runner):
    with (
        patch("envault.cli_rating._get_vault"),
        patch("envault.cli_rating.rate_secret", return_value=_GOOD_RESULT),
    ):
        result = runner.invoke(
            rating_group,
            ["score", "prod", "API_KEY", "--vault-file", "v.json", "--passphrase", "pw", "--json"],
            catch_exceptions=False,
        )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["score"] == 85
    assert data["level"] == "strong"


def test_score_missing_secret_exits_nonzero(runner):
    with (
        patch("envault.cli_rating._get_vault"),
        patch("envault.cli_rating.rate_secret", side_effect=RatingError("not found")),
    ):
        result = runner.invoke(
            rating_group,
            ["score", "prod", "MISSING", "--vault-file", "v.json", "--passphrase", "pw"],
        )
    assert result.exit_code != 0


def test_all_success(runner):
    results = [_GOOD_RESULT, RatingResult("DB_PASS", "prod", 40, "fair", {})]
    with (
        patch("envault.cli_rating._get_vault"),
        patch("envault.cli_rating.rate_all", return_value=results),
    ):
        result = runner.invoke(
            rating_group,
            ["all", "prod", "--vault-file", "v.json", "--passphrase", "pw"],
            catch_exceptions=False,
        )
    assert result.exit_code == 0
    assert "API_KEY" in result.output
    assert "DB_PASS" in result.output


def test_all_min_level_filter(runner):
    results = [_GOOD_RESULT, RatingResult("DB_PASS", "prod", 40, "fair", {})]
    with (
        patch("envault.cli_rating._get_vault"),
        patch("envault.cli_rating.rate_all", return_value=results),
    ):
        result = runner.invoke(
            rating_group,
            ["all", "prod", "--vault-file", "v.json", "--passphrase", "pw", "--min-level", "strong"],
            catch_exceptions=False,
        )
    assert result.exit_code == 0
    assert "API_KEY" in result.output
    assert "DB_PASS" not in result.output


def test_all_empty(runner):
    with (
        patch("envault.cli_rating._get_vault"),
        patch("envault.cli_rating.rate_all", return_value=[]),
    ):
        result = runner.invoke(
            rating_group,
            ["all", "prod", "--vault-file", "v.json", "--passphrase", "pw"],
            catch_exceptions=False,
        )
    assert result.exit_code == 0
    assert "No secrets" in result.output
