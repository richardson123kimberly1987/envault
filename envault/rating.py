"""Secret rating module: assigns a quality rating to secrets based on multiple factors."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

RATING_LEVELS = ["poor", "fair", "good", "strong", "excellent"]


class RatingError(Exception):
    """Raised when rating operations fail."""


@dataclass
class RatingResult:
    secret_name: str
    environment: str
    score: int          # 0-100
    level: str          # one of RATING_LEVELS
    factors: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "secret_name": self.secret_name,
            "environment": self.environment,
            "score": self.score,
            "level": self.level,
            "factors": self.factors,
        }


def _level_for_score(score: int) -> str:
    if score >= 90:
        return "excellent"
    if score >= 70:
        return "strong"
    if score >= 50:
        return "good"
    if score >= 30:
        return "fair"
    return "poor"


def _get_entry_or_raise(vault: Any, environment: str, secret_name: str) -> Any:
    entry = vault.get_secret(environment, secret_name)
    if entry is None:
        raise RatingError(f"Secret '{secret_name}' not found in '{environment}'")
    return entry


def rate_secret(vault: Any, environment: str, secret_name: str) -> RatingResult:
    """Rate a single secret and return a RatingResult."""
    entry = _get_entry_or_raise(vault, environment, secret_name)
    raw = entry.decrypt() if callable(getattr(entry, "decrypt", None)) else ""
    data = entry.to_dict()

    factors: dict[str, int] = {}

    # Length factor (max 30)
    length = len(raw)
    factors["length"] = min(30, length * 2)

    # Complexity factor (max 30): presence of upper, lower, digit, special
    classes = [
        any(c.isupper() for c in raw),
        any(c.islower() for c in raw),
        any(c.isdigit() for c in raw),
        any(not c.isalnum() for c in raw),
    ]
    factors["complexity"] = sum(classes) * 7  # max 28, close enough

    # Metadata factor (max 20): has tags, has description
    meta = 0
    if data.get("tags"):
        meta += 10
    if data.get("description"):
        meta += 10
    factors["metadata"] = meta

    # Freshness factor (max 20): not expired, has expiry set
    freshness = 0
    if data.get("expiry") and not data.get("expired", False):
        freshness = 20
    elif not data.get("expired", False):
        freshness = 10
    factors["freshness"] = freshness

    score = min(100, sum(factors.values()))
    level = _level_for_score(score)
    return RatingResult(
        secret_name=secret_name,
        environment=environment,
        score=score,
        level=level,
        factors=factors,
    )


def rate_all(vault: Any, environment: str) -> list[RatingResult]:
    """Rate all secrets in an environment."""
    results = []
    for name in vault.list_secrets(environment):
        try:
            results.append(rate_secret(vault, environment, name))
        except RatingError:
            pass
    return results
