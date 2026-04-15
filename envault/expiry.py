"""Secret expiry and TTL management for envault."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

EXPIRY_DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class ExpiryError(Exception):
    """Raised when an expiry operation fails."""


@dataclass
class ExpiryResult:
    environment: str
    key: str
    expires_at: Optional[str]
    is_expired: bool
    days_remaining: Optional[int]

    def to_dict(self) -> dict:
        return {
            "environment": self.environment,
            "key": self.key,
            "expires_at": self.expires_at,
            "is_expired": self.is_expired,
            "days_remaining": self.days_remaining,
        }


def _parse_expiry(expires_at: str) -> datetime:
    try:
        return datetime.strptime(expires_at, EXPIRY_DATE_FORMAT).replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ExpiryError(f"Invalid expiry date format: {expires_at!r}") from exc


def set_expiry(vault, environment: str, key: str, expires_at: str) -> ExpiryResult:
    """Set an expiry date on a secret. expires_at must be ISO-8601 UTC."""
    entry = vault.get_secret(environment, key)
    if entry is None:
        raise ExpiryError(f"Secret '{key}' not found in environment '{environment}'")

    _parse_expiry(expires_at)  # validate format

    data = entry.to_dict()
    data["expires_at"] = expires_at
    vault.set_secret(environment, key, data["value"], metadata={"expires_at": expires_at})
    return check_expiry(vault, environment, key)


def check_expiry(vault, environment: str, key: str) -> ExpiryResult:
    """Return expiry status for a single secret."""
    entry = vault.get_secret(environment, key)
    if entry is None:
        raise ExpiryError(f"Secret '{key}' not found in environment '{environment}'")

    d = entry.to_dict()
    expires_at = d.get("expires_at") or d.get("metadata", {}).get("expires_at")

    if not expires_at:
        return ExpiryResult(environment, key, None, False, None)

    expiry_dt = _parse_expiry(expires_at)
    now = datetime.now(timezone.utc)
    delta = expiry_dt - now
    is_expired = delta.total_seconds() <= 0
    days_remaining = None if is_expired else max(0, delta.days)
    return ExpiryResult(environment, key, expires_at, is_expired, days_remaining)


def list_expiring(vault, environment: str, within_days: int = 30) -> List[ExpiryResult]:
    """List secrets expiring within *within_days* days (including already expired)."""
    results = []
    for key in vault.list_secrets(environment):
        try:
            result = check_expiry(vault, environment, key)
        except ExpiryError:
            continue
        if result.expires_at is None:
            continue
        if result.is_expired or (result.days_remaining is not None and result.days_remaining <= within_days):
            results.append(result)
    return results
