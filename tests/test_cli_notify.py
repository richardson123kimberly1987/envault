"""Tests for envault.cli_notify."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from envault.cli_notify import notify_group
from envault.notify import NotifyResult


@pytest.fixture()
def runner(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return CliRunner()


def _invoke(runner, *args):
    return runner.invoke(notify_group, list(args), catch_exceptions=False)


def test_list_empty(runner):
    result = _invoke(runner, "list")
    assert result.exit_code == 0
    assert "No webhooks" in result.output


def test_add_creates_config(runner):
    result = _invoke(runner, "add", "https://hooks.example.com/x")
    assert result.exit_code == 0
    assert "registered" in result.output
    data = json.loads(Path("envault_notify.json").read_text())
    assert len(data) == 1
    assert data[0]["webhook_url"] == "https://hooks.example.com/x"


def test_add_with_custom_events(runner):
    _invoke(runner, "add", "https://x.com", "--events", "set,rotate")
    data = json.loads(Path("envault_notify.json").read_text())
    assert data[0]["events"] == ["set", "rotate"]


def test_list_shows_webhooks(runner):
    _invoke(runner, "add", "https://a.com")
    result = _invoke(runner, "list")
    assert "https://a.com" in result.output


def test_remove_webhook(runner):
    _invoke(runner, "add", "https://a.com")
    _invoke(runner, "add", "https://b.com")
    result = _invoke(runner, "remove", "0")
    assert result.exit_code == 0
    data = json.loads(Path("envault_notify.json").read_text())
    assert len(data) == 1
    assert data[0]["webhook_url"] == "https://b.com"


def test_remove_invalid_index(runner):
    _invoke(runner, "add", "https://a.com")
    result = runner.invoke(notify_group, ["remove", "99"])
    assert result.exit_code != 0


def test_test_cmd_success(runner):
    _invoke(runner, "add", "https://hooks.example.com/ok")
    ok = NotifyResult("set", "TEST_SECRET", "dev", "https://hooks.example.com/ok", True, 200)
    with patch("envault.cli_notify.send_notification", return_value=ok):
        result = _invoke(runner, "test", "0")
    assert "200" in result.output


def test_test_cmd_failure(runner):
    _invoke(runner, "add", "https://hooks.example.com/fail")
    fail = NotifyResult("set", "TEST_SECRET", "dev", "https://hooks.example.com/fail", False, None, "timeout")
    with patch("envault.cli_notify.send_notification", return_value=fail):
        result = runner.invoke(notify_group, ["test", "0"])
    assert result.exit_code != 0
