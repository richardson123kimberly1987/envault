"""expire_warn: warn when secrets are approaching expiry."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

EXPIRE_WARN_EVENTS = ["secret.expiry_warning", "secret.expired"]


class ExpireWarnError(Exception):
    """Raised when expire-warn operations fail."""


@dataclass
class ExpireWarnResult:
    key: str
    environment: str
    expires_at: Optional[str]
    days_remaining: Optional[int]
    is_expired: bool
    warning: bool

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "environment": self.environment,
            "expires_at": self.expires_at,
            "days_remaining": self.days_remaining,
            "is_expired": self.is_expired,
            "warning": self.warning,
        }


def _days_remaining(expires_at: str) -> int:
    expiry = datetime.fromisoformat(expires_at)
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    now = datetime.now(tz=timezone.utc)
    delta = expiry - now
    return delta.days


def check_expiry_warning(vault, environment: str, key: str, threshold_days: int = 7) -> ExpireWarnResult:
    """Check whether a secret is expired or within the warning threshold."""
    entry = vault.get_secret(environment, key)
    if entry is None:
        raise ExpireWarnError(f"Secret '{key}' not found in environment '{environment}'.")

    data = entry.to_dict()
    expires_at = data.get("expires_at")

    if not expires_at:
        return ExpireWarnResult(
            key=key,
            environment=environment,
            expires_at=None,
            days_remaining=None,
            is_expired=False,
            warning=False,
        )

    days = _days_remaining(expires_at)
    is_expired = days < 0
    warning = not is_expired and days <= threshold_days

    return ExpireWarnResult(
        key=key,
        environment=environment,
        expires_at=expires_at,
        days_remaining=days,
        is_expired=is_expired,
        warning=warning,
    )


def check_all_expiry_warnings(vault, environment: str, threshold_days: int = 7) -> List[ExpireWarnResult]:
    """Check all secrets in an environment for expiry warnings."""
    results = []
    for key in vault.list_secrets(environment):
        result = check_expiry_warning(vault, environment, key, threshold_days)
        if result.is_expired or result.warning:
            results.append(result)
    return results
