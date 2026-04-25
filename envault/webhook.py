"""Webhook delivery for envault secret events."""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import urllib.request
import urllib.error

WEBHOOK_EVENTS = [
    "secret.set",
    "secret.rotated",
    "secret.deleted",
    "secret.expired",
    "vault.saved",
]


class WebhookError(Exception):
    """Raised when a webhook operation fails."""


@dataclass
class WebhookConfig:
    url: str
    events: List[str] = field(default_factory=list)
    secret: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"url": self.url, "events": self.events, "secret": self.secret}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WebhookConfig":
        return cls(
            url=data["url"],
            events=data.get("events", []),
            secret=data.get("secret"),
        )


@dataclass
class WebhookResult:
    url: str
    event: str
    status_code: int
    delivered: bool
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "event": self.event,
            "status_code": self.status_code,
            "delivered": self.delivered,
            "error": self.error,
        }


def _sign_payload(payload: bytes, secret: str) -> str:
    return hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


def deliver_webhook(
    config: WebhookConfig,
    event: str,
    payload: Dict[str, Any],
) -> WebhookResult:
    """Deliver a webhook payload to the configured URL."""
    if event not in WEBHOOK_EVENTS:
        raise WebhookError(f"Unknown event: {event!r}. Valid: {WEBHOOK_EVENTS}")

    if config.events and event not in config.events:
        return WebhookResult(url=config.url, event=event, status_code=0, delivered=False, error="event filtered")

    body = json.dumps({"event": event, "timestamp": datetime.now(timezone.utc).isoformat(), "data": payload}).encode()
    headers = {"Content-Type": "application/json", "X-Envault-Event": event}
    if config.secret:
        headers["X-Envault-Signature"] = _sign_payload(body, config.secret)

    req = urllib.request.Request(config.url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return WebhookResult(url=config.url, event=event, status_code=resp.status, delivered=resp.status < 300)
    except urllib.error.HTTPError as exc:
        return WebhookResult(url=config.url, event=event, status_code=exc.code, delivered=False, error=str(exc))
    except Exception as exc:
        return WebhookResult(url=config.url, event=event, status_code=0, delivered=False, error=str(exc))
