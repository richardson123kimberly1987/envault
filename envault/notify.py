"""Notification hooks for secret lifecycle events."""
from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

NOTIFY_EVENTS = ["set", "rotate", "delete", "expire", "access_denied"]


class NotifyError(Exception):
    """Raised when a notification fails."""


@dataclass
class NotifyResult:
    event: str
    secret_name: str
    environment: str
    webhook_url: str
    success: bool
    status_code: Optional[int] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event": self.event,
            "secret_name": self.secret_name,
            "environment": self.environment,
            "webhook_url": self.webhook_url,
            "success": self.success,
            "status_code": self.status_code,
            "error": self.error,
        }


@dataclass
class NotifyConfig:
    webhook_url: str
    events: List[str] = field(default_factory=lambda: list(NOTIFY_EVENTS))
    timeout: int = 5

    def to_dict(self) -> Dict[str, Any]:
        return {"webhook_url": self.webhook_url, "events": self.events, "timeout": self.timeout}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NotifyConfig":
        return cls(
            webhook_url=data["webhook_url"],
            events=data.get("events", list(NOTIFY_EVENTS)),
            timeout=data.get("timeout", 5),
        )


def send_notification(
    config: NotifyConfig,
    event: str,
    secret_name: str,
    environment: str,
    extra: Optional[Dict[str, Any]] = None,
) -> NotifyResult:
    if event not in config.events:
        return NotifyResult(event, secret_name, environment, config.webhook_url, True, None, "skipped")

    payload = json.dumps(
        {"event": event, "secret": secret_name, "environment": environment, **(extra or {})}
    ).encode()
    req = urllib.request.Request(
        config.webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=config.timeout) as resp:
            return NotifyResult(event, secret_name, environment, config.webhook_url, True, resp.status)
    except Exception as exc:  # noqa: BLE001
        return NotifyResult(event, secret_name, environment, config.webhook_url, False, None, str(exc))
