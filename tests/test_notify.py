"""Tests for envault.notify."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from envault.notify import (
    NOTIFY_EVENTS,
    NotifyConfig,
    NotifyResult,
    send_notification,
)


def _config(events=None):
    return NotifyConfig(
        webhook_url="https://hooks.example.com/test",
        events=events if events is not None else list(NOTIFY_EVENTS),
        timeout=3,
    )


def test_notify_events_constant_not_empty():
    assert len(NOTIFY_EVENTS) > 0


def test_notify_config_to_dict_round_trip():
    cfg = _config()
    d = cfg.to_dict()
    cfg2 = NotifyConfig.from_dict(d)
    assert cfg2.webhook_url == cfg.webhook_url
    assert cfg2.events == cfg.events
    assert cfg2.timeout == cfg.timeout


def test_notify_result_to_dict():
    r = NotifyResult("set", "DB_PASS", "prod", "https://x", True, 200)
    d = r.to_dict()
    assert d["event"] == "set"
    assert d["success"] is True
    assert d["status_code"] == 200


def test_send_notification_skipped_when_event_not_in_config():
    cfg = _config(events=["rotate"])
    result = send_notification(cfg, "set", "KEY", "dev")
    assert result.success is True
    assert result.error == "skipped"


def test_send_notification_success():
    cfg = _config()
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__ = lambda s: mock_resp
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        result = send_notification(cfg, "set", "API_KEY", "staging")

    assert result.success is True
    assert result.status_code == 200
    assert result.error is None


def test_send_notification_failure_on_exception():
    cfg = _config()
    with patch("urllib.request.urlopen", side_effect=OSError("connection refused")):
        result = send_notification(cfg, "rotate", "SECRET", "prod")

    assert result.success is False
    assert "connection refused" in result.error


def test_send_notification_includes_extra_payload():
    cfg = _config()
    captured = {}

    def fake_urlopen(req, timeout):
        import json
        captured["body"] = json.loads(req.data)
        mock_resp = MagicMock()
        mock_resp.status = 204
        mock_resp.__enter__ = lambda s: mock_resp
        mock_resp.__exit__ = MagicMock(return_value=False)
        return mock_resp

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        send_notification(cfg, "expire", "TOKEN", "prod", extra={"days_left": 0})

    assert captured["body"]["days_left"] == 0
    assert captured["body"]["event"] == "expire"
