"""TTL (time-to-live) management for secrets."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

TTL_UNITS = ("seconds", "minutes", "hours", "days")


class TTLError(Exception):
    """Raised when a TTL operation fails."""


@dataclass
class TTLResult:
    secret: str
    environment: str
    ttl_seconds: int
    expires_at: str
    already_expired: bool

    def to_dict(self) -> dict:
        return {
            "secret": self.secret,
            "environment": self.environment,
            "ttl_seconds": self.ttl_seconds,
            "expires_at": self.expires_at,
            "already_expired": self.already_expired,
        }


def _parse_ttl(value: int, unit: str) -> int:
    """Convert a value+unit pair to total seconds."""
    if unit not in TTL_UNITS:
        raise TTLError(f"Unknown TTL unit '{unit}'. Choose from: {', '.join(TTL_UNITS)}")
    if value <= 0:
        raise TTLError("TTL value must be a positive integer.")
    multipliers = {"seconds": 1, "minutes": 60, "hours": 3600, "days": 86400}
    return value * multipliers[unit]


def set_ttl(vault, environment: str, secret: str, value: int, unit: str = "seconds") -> TTLResult:
    """Attach a TTL to a secret entry."""
    entry = vault.get_secret(environment, secret)
    if entry is None:
        raise TTLError(f"Secret '{secret}' not found in environment '{environment}'.")

    ttl_seconds = _parse_ttl(value, unit)
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
    expires_str = expires_at.isoformat()

    data = entry.to_dict()
    data.setdefault("metadata", {})
    data["metadata"]["ttl_seconds"] = ttl_seconds
    data["metadata"]["ttl_expires_at"] = expires_str
    vault.set_secret(environment, secret, data["value"], data["metadata"])

    return TTLResult(
        secret=secret,
        environment=environment,
        ttl_seconds=ttl_seconds,
        expires_at=expires_str,
        already_expired=False,
    )


def check_ttl(vault, environment: str, secret: str) -> Optional[TTLResult]:
    """Return TTL status for a secret, or None if no TTL is set."""
    entry = vault.get_secret(environment, secret)
    if entry is None:
        raise TTLError(f"Secret '{secret}' not found in environment '{environment}'.")

    data = entry.to_dict()
    metadata = data.get("metadata") or {}
    ttl_seconds = metadata.get("ttl_seconds")
    expires_str = metadata.get("ttl_expires_at")

    if ttl_seconds is None or expires_str is None:
        return None

    expires_at = datetime.fromisoformat(expires_str)
    already_expired = datetime.now(timezone.utc) >= expires_at

    return TTLResult(
        secret=secret,
        environment=environment,
        ttl_seconds=ttl_seconds,
        expires_at=expires_str,
        already_expired=already_expired,
    )
