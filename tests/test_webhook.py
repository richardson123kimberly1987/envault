"""Tests for envault.webhook."""
from __future__ import annotations

import hashlib
import hmac
import json
from unittest.mock import MagicMock, patch

import pytest

from envault.webhook import (
    WEBHOOK_EVENTS,
    WebhookConfig,
    WebhookError,
    WebhookResult,
    _sign_payload,
    deliver_webhook,
)


# ---------------------------------------------------------------------------
# WebhookConfig
# ---------------------------------------------------------------------------

def test_webhook_events_constant_not_empty():
    assert len(WEBHOOK_EVENTS) > 0


def test_webhook_config_to_dict_round_trip():
    cfg = WebhookConfig(url="https://example.com/hook", events=["secret.set"], secret="s3cr3t")
    d = cfg.to_dict()
    restored = WebhookConfig.from_dict(d)
    assert restored.url == cfg.url
    assert restored.events == cfg.events
    assert restored.secret == cfg.secret


def test_webhook_config_defaults():
    cfg = WebhookConfig.from_dict({"url": "https://x.com"})
    assert cfg.events == []
    assert cfg.secret is None


# ---------------------------------------------------------------------------
# _sign_payload
# ---------------------------------------------------------------------------

def test_sign_payload_produces_hex():
    sig = _sign_payload(b"hello", "mysecret")
    expected = hmac.new(b"mysecret", b"hello", hashlib.sha256).hexdigest()
    assert sig == expected


# ---------------------------------------------------------------------------
# deliver_webhook
# ---------------------------------------------------------------------------

def _make_mock_response(status: int):
    resp = MagicMock()
    resp.status = status
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


def test_deliver_webhook_unknown_event_raises():
    cfg = WebhookConfig(url="https://example.com")
    with pytest.raises(WebhookError, match="Unknown event"):
        deliver_webhook(cfg, "not.an.event", {})


def test_deliver_webhook_filtered_event():
    cfg = WebhookConfig(url="https://example.com", events=["secret.set"])
    result = deliver_webhook(cfg, "vault.saved", {})
    assert not result.delivered
    assert result.error == "event filtered"
    assert result.status_code == 0


def test_deliver_webhook_success():
    cfg = WebhookConfig(url="https://example.com/hook")
    mock_resp = _make_mock_response(200)
    with patch("urllib.request.urlopen", return_value=mock_resp):
        result = deliver_webhook(cfg, "secret.set", {"key": "DB_PASS"})
    assert result.delivered
    assert result.status_code == 200
    assert result.error is None


def test_deliver_webhook_server_error():
    import urllib.error
    cfg = WebhookConfig(url="https://example.com/hook")
    with patch("urllib.request.urlopen", side_effect=urllib.error.HTTPError(None, 500, "Server Error", {}, None)):
        result = deliver_webhook(cfg, "secret.rotated", {})
    assert not result.delivered
    assert result.status_code == 500


def test_deliver_webhook_connection_error():
    cfg = WebhookConfig(url="https://example.com/hook")
    with patch("urllib.request.urlopen", side_effect=OSError("connection refused")):
        result = deliver_webhook(cfg, "secret.deleted", {})
    assert not result.delivered
    assert "connection refused" in (result.error or "")


def test_deliver_webhook_adds_signature_header():
    cfg = WebhookConfig(url="https://example.com/hook", secret="tok")
    captured = {}

    def fake_urlopen(req, timeout):
        captured["headers"] = dict(req.headers)
        return _make_mock_response(204)

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        deliver_webhook(cfg, "vault.saved", {})

    assert "X-envault-signature" in captured["headers"]


def test_webhook_result_to_dict():
    r = WebhookResult(url="https://x.com", event="secret.set", status_code=200, delivered=True)
    d = r.to_dict()
    assert d["delivered"] is True
    assert d["event"] == "secret.set"
