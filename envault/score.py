"""Secret strength scoring for envault."""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import List

SCORE_LEVELS = ["critical", "weak", "fair", "strong", "excellent"]


class ScoreError(Exception):
    """Raised when scoring fails."""


@dataclass
class ScoreResult:
    secret_name: str
    environment: str
    score: int          # 0-100
    level: str
    suggestions: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "secret_name": self.secret_name,
            "environment": self.environment,
            "score": self.score,
            "level": self.level,
            "suggestions": self.suggestions,
        }


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    freq = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def score_secret(vault, name: str, environment: str) -> ScoreResult:
    """Score the strength of a single secret's value."""
    entry = vault.get_secret(name, environment)
    if entry is None:
        raise ScoreError(f"Secret '{name}' not found in environment '{environment}'")

    try:
        data = entry.to_dict()
        value: str = data.get("value", "")
    except Exception as exc:  # pragma: no cover
        raise ScoreError(f"Could not read secret value: {exc}") from exc

    suggestions: List[str] = []
    points = 0

    length = len(value)
    if length >= 32:
        points += 40
    elif length >= 16:
        points += 25
        suggestions.append("Use at least 32 characters for stronger secrets.")
    elif length >= 8:
        points += 10
        suggestions.append("Use at least 16 characters for stronger secrets.")
    else:
        suggestions.append("Secret is very short; use at least 16 characters.")

    ent = _entropy(value)
    if ent >= 4.0:
        points += 30
    elif ent >= 3.0:
        points += 20
        suggestions.append("Increase character variety to improve entropy.")
    else:
        points += 5
        suggestions.append("Secret has low entropy; mix letters, digits, and symbols.")

    if re.search(r"[A-Z]", value):
        points += 5
    else:
        suggestions.append("Add uppercase letters.")
    if re.search(r"[a-z]", value):
        points += 5
    else:
        suggestions.append("Add lowercase letters.")
    if re.search(r"\d", value):
        points += 10
    else:
        suggestions.append("Add digits.")
    if re.search(r"[^A-Za-z0-9]", value):
        points += 10
    else:
        suggestions.append("Add special characters (e.g. !@#$%).")

    score = min(100, max(0, points))

    if score >= 85:
        level = "excellent"
    elif score >= 65:
        level = "strong"
    elif score >= 45:
        level = "fair"
    elif score >= 25:
        level = "weak"
    else:
        level = "critical"

    return ScoreResult(
        secret_name=name,
        environment=environment,
        score=score,
        level=level,
        suggestions=suggestions,
    )


def score_all(vault, environment: str) -> List[ScoreResult]:
    """Score all secrets in an environment."""
    results = []
    for name in vault.list_secrets(environment):
        try:
            results.append(score_secret(vault, name, environment))
        except ScoreError:
            continue
    return results
