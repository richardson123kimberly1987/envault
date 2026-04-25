"""Quota management for secrets per environment."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional

DEFAULT_QUOTA = 100


class QuotaError(Exception):
    """Raised when a quota operation fails."""


@dataclass
class QuotaResult:
    environment: str
    limit: int
    used: int
    remaining: int
    exceeded: bool

    def to_dict(self) -> dict:
        return {
            "environment": self.environment,
            "limit": self.limit,
            "used": self.used,
            "remaining": self.remaining,
            "exceeded": self.exceeded,
        }


def _load_quotas(vault) -> Dict[str, int]:
    """Load quota limits from vault metadata."""
    meta = getattr(vault, "meta", {}) or {}
    return dict(meta.get("quotas", {}))


def _save_quotas(vault, quotas: Dict[str, int]) -> None:
    """Persist quota limits into vault metadata."""
    if not hasattr(vault, "meta") or vault.meta is None:
        vault.meta = {}
    vault.meta["quotas"] = quotas
    vault.save()


def set_quota(vault, environment: str, limit: int) -> QuotaResult:
    """Set the maximum number of secrets allowed in *environment*."""
    if limit < 0:
        raise QuotaError("Quota limit must be a non-negative integer.")
    quotas = _load_quotas(vault)
    quotas[environment] = limit
    _save_quotas(vault, quotas)
    used = len(vault.list_secrets(environment))
    remaining = max(limit - used, 0)
    return QuotaResult(
        environment=environment,
        limit=limit,
        used=used,
        remaining=remaining,
        exceeded=used > limit,
    )


def check_quota(vault, environment: str) -> QuotaResult:
    """Return the current quota status for *environment*."""
    quotas = _load_quotas(vault)
    limit = quotas.get(environment, DEFAULT_QUOTA)
    used = len(vault.list_secrets(environment))
    remaining = max(limit - used, 0)
    return QuotaResult(
        environment=environment,
        limit=limit,
        used=used,
        remaining=remaining,
        exceeded=used > limit,
    )


def enforce_quota(vault, environment: str) -> None:
    """Raise *QuotaError* if the environment has exceeded its quota."""
    result = check_quota(vault, environment)
    if result.exceeded:
        raise QuotaError(
            f"Environment '{environment}' has exceeded its quota of "
            f"{result.limit} secrets (currently {result.used})."
        )
