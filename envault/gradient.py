"""Gradient: compute a sensitivity gradient score for secrets based on metadata."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class GradientError(Exception):
    """Raised when gradient computation fails."""


# Weights for each metadata dimension (0-1 scale)
_DIMENSION_WEIGHTS: Dict[str, float] = {
    "classification": 0.30,
    "scope": 0.20,
    "expiry": 0.15,
    "tags": 0.15,
    "lock": 0.10,
    "priority": 0.10,
}

GRADIENT_LEVELS = ["negligible", "low", "medium", "high", "critical"]


@dataclass
class GradientResult:
    secret: str
    environment: str
    score: float  # 0.0 – 1.0
    level: str
    dimensions: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "secret": self.secret,
            "environment": self.environment,
            "score": round(self.score, 4),
            "level": self.level,
            "dimensions": {k: round(v, 4) for k, v in self.dimensions.items()},
        }


def _level_for_score(score: float) -> str:
    if score < 0.2:
        return "negligible"
    if score < 0.4:
        return "low"
    if score < 0.6:
        return "medium"
    if score < 0.8:
        return "high"
    return "critical"


def _get_entry_or_raise(vault: Any, environment: str, secret: str) -> Any:
    entry = vault.get_secret(environment, secret)
    if entry is None:
        raise GradientError(f"Secret '{secret}' not found in environment '{environment}'")
    return entry


def compute_gradient(vault: Any, environment: str, secret: str) -> GradientResult:
    """Compute a sensitivity gradient for *secret* in *environment*."""
    entry = _get_entry_or_raise(vault, environment, secret)
    meta: Dict[str, Any] = entry.to_dict()

    dims: Dict[str, float] = {}

    # classification dimension
    cls_map = {"public": 0.0, "internal": 0.4, "confidential": 0.7, "secret": 1.0}
    classification = meta.get("classification", "internal")
    dims["classification"] = cls_map.get(str(classification).lower(), 0.4)

    # scope dimension — more scopes = wider blast radius
    scopes: List[str] = meta.get("scopes", [])
    dims["scope"] = min(len(scopes) / 5.0, 1.0) if scopes else 0.2

    # expiry dimension — no expiry is riskier
    dims["expiry"] = 0.0 if meta.get("expires_at") else 0.8

    # tags dimension — presence of sensitive tags raises score
    sensitive_tags = {"pii", "payment", "credential", "private", "sensitive"}
    tags: List[str] = meta.get("tags", [])
    matched = len(sensitive_tags.intersection({t.lower() for t in tags}))
    dims["tags"] = min(matched / 3.0, 1.0)

    # lock dimension — unlocked secrets are riskier
    dims["lock"] = 0.0 if meta.get("locked") else 0.9

    # priority dimension
    priority_map = {"low": 0.2, "medium": 0.5, "high": 0.8, "critical": 1.0}
    priority = meta.get("priority", "medium")
    dims["priority"] = priority_map.get(str(priority).lower(), 0.5)

    score = sum(_DIMENSION_WEIGHTS[k] * v for k, v in dims.items())
    return GradientResult(
        secret=secret,
        environment=environment,
        score=score,
        level=_level_for_score(score),
        dimensions=dims,
    )


def compute_gradient_all(
    vault: Any, environment: str
) -> List[GradientResult]:
    """Compute gradient for every secret in *environment*."""
    results: List[GradientResult] = []
    for secret in vault.list_secrets(environment):
        try:
            results.append(compute_gradient(vault, environment, secret))
        except GradientError:
            continue
    results.sort(key=lambda r: r.score, reverse=True)
    return results
