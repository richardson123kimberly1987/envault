"""Tests for envault.cli_webhook."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from envault.cli_webhook import webhook_group
from envault.webhook import WebhookResult


@pytest.fixture()
def runner(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return CliRunner()


def _invoke(runner, *args):
    return runner.invoke(webhook_group, list(args), catch_exceptions=False)


def _read_webhooks(tmp_path: Path):
    p = tmp_path / ".envault_webhooks.json"
    if not p.exists():
        return []
    return json.loads(p.read_text())


def test_list_empty(runner):
    result = _invoke(runner, "list")
    assert result.exit_code == 0
    assert "No webhooks" in result.output


def test_add_creates_webhook(runner, tmp_path):
    result = _invoke(runner, "add", "https://example.com/hook")
    assert result.exit_code == 0
    assert "Webhook added" in result.output
    data = _read_webhooks(tmp_path)
    assert len(data) == 1
    assert data[0]["url"] == "https://example.com/hook"


def test_add_with_specific_events(runner, tmp_path):
    result = _invoke(runner, "add", "https://x.com", "--event", "secret.set", "--event", "secret.rotated")
    assert result.exit_code == 0
    data = _read_webhooks(tmp_path)
    assert data[0]["events"] == ["secret.set", "secret.rotated"]


def test_add_unknown_event_shows_error(runner):
    result = runner.invoke(webhook_group, ["add", "https://x.com", "--event", "bad.event"])
    assert result.exit_code != 0
    assert "Unknown event" in result.output


def test_add_with_secret(runner, tmp_path):
    _invoke(runner, "add", "https://x.com", "--secret", "tok123")
    data = _read_webhooks(tmp_path)
    assert data[0]["secret"] == "tok123"


def test_list_shows_registered(runner):
    _invoke(runner, "add", "https://a.com")
    result = _invoke(runner, "list")
    assert "https://a.com" in result.output


def test_remove_existing(runner, tmp_path):
    _invoke(runner, "add", "https://a.com")
    result = _invoke(runner, "remove", "https://a.com")
    assert result.exit_code == 0
    assert "removed" in result.output
    assert _read_webhooks(tmp_path) == []


def test_remove_nonexistent_shows_error(runner):
    result = runner.invoke(webhook_group, ["remove", "https://nothere.com"])
    assert result.exit_code != 0
    assert "No webhook found" in result.output


def test_test_cmd_success(runner):
    _invoke(runner, "add", "https://hook.example.com")
    fake_result = WebhookResult(url="https://hook.example.com", event="secret.set", status_code=200, delivered=True)
    with patch("envault.cli_webhook.deliver_webhook", return_value=fake_result):
        result = _invoke(runner, "test", "https://hook.example.com")
    assert "Delivered" in result.output
    assert "200" in result.output


def test_test_cmd_failure(runner):
    _invoke(runner, "add", "https://hook.example.com")
    fake_result = WebhookResult(url="https://hook.example.com", event="secret.set", status_code=500, delivered=False, error="server error")
    with patch("envault.cli_webhook.deliver_webhook", return_value=fake_result):
        result = _invoke(runner, "test", "https://hook.example.com")
    assert "Failed" in result.output
