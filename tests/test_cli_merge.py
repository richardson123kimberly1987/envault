import json
import pytest
from click.testing import CliRunner
from unittest.mock import MagicMock, patch
from envault.cli_merge import merge_group
from envault.merge import MergeResult, MergeError


@pytest.fixture
def runner():
    return CliRunner()


def _fake_result(merged=2, skipped=1, conflicts=0, details=None):
    return MergeResult(
        source="staging",
        target="production",
        merged=merged,
        skipped=skipped,
        conflicts=conflicts,
        details=details or {"KEY_A": "merged", "KEY_B": "merged", "KEY_C": "skipped"},
    )


def _invoke(runner, args, result=None, error=None):
    with patch("envault.cli_merge._get_vault") as mock_vault, \
         patch("envault.cli_merge.merge_environments") as mock_merge:
        vault = MagicMock()
        mock_vault.return_value = vault
        if error:
            mock_merge.side_effect = error
        else:
            mock_merge.return_value = result or _fake_result()
        out = runner.invoke(
            merge_group,
            ["envs"] + args + ["--passphrase", "secret"],
        )
        return out, mock_merge, vault


def test_merge_success_saves_vault(runner):
    out, mock_merge, vault = _invoke(runner, ["staging", "production"])
    assert out.exit_code == 0
    assert "Merged 2 secret(s)" in out.output
    vault.save.assert_called_once()


def test_merge_dry_run_does_not_save(runner):
    out, _, vault = _invoke(runner, ["staging", "production", "--dry-run"])
    assert out.exit_code == 0
    assert "dry-run" in out.output
    vault.save.assert_not_called()


def test_merge_shows_detail_lines(runner):
    out, _, _ = _invoke(runner, ["staging", "production"])
    assert "KEY_A" in out.output
    assert "KEY_B" in out.output


def test_merge_error_raises_click_exception(runner):
    out, _, _ = _invoke(
        runner,
        ["staging", "production"],
        error=MergeError("source env not found"),
    )
    assert out.exit_code != 0
    assert "source env not found" in out.output


def test_merge_strategy_passed_through(runner):
    out, mock_merge, _ = _invoke(
        runner, ["staging", "production", "--strategy", "overwrite"]
    )
    _, kwargs = mock_merge.call_args
    assert kwargs.get("strategy") == "overwrite"


def test_merge_default_strategy_is_keep(runner):
    out, mock_merge, _ = _invoke(runner, ["staging", "production"])
    _, kwargs = mock_merge.call_args
    assert kwargs.get("strategy") == "keep"
