"""Entropy analysis for secret values in envault."""
from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Optional


class EntropyError(Exception):
    """Raised when entropy analysis fails."""


@dataclass
class EntropyResult:
    secret_name: str
    environment: str
    entropy: float
    length: int
    rating: str
    unique_chars: int

    def to_dict(self) -> Dict:
        return {
            "secret_name": self.secret_name,
            "environment": self.environment,
            "entropy": round(self.entropy, 4),
            "length": self.length,
            "rating": self.rating,
            "unique_chars": self.unique_chars,
        }


_RATINGS = [
    (0.0, "very_low"),
    (2.0, "low"),
    (3.5, "medium"),
    (4.5, "high"),
    (float("inf"), "very_high"),
]


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _rate(entropy: float) -> str:
    for threshold, label in _RATINGS:
        if entropy < threshold:
            return label
    return "very_high"


def analyze_entropy(vault, secret_name: str, environment: str) -> EntropyResult:
    """Compute Shannon entropy for a single secret value."""
    entry = vault.get_secret(secret_name, environment)
    if entry is None:
        raise EntropyError(
            f"Secret '{secret_name}' not found in environment '{environment}'."
        )
    value: str = entry.decrypt()
    entropy = _shannon_entropy(value)
    return EntropyResult(
        secret_name=secret_name,
        environment=environment,
        entropy=entropy,
        length=len(value),
        rating=_rate(entropy),
        unique_chars=len(set(value)),
    )


def analyze_all_entropy(
    vault, environment: str
) -> List[EntropyResult]:
    """Compute entropy for every secret in the given environment."""
    results: List[EntropyResult] = []
    for name in vault.list_secrets(environment):
        try:
            results.append(analyze_entropy(vault, name, environment))
        except EntropyError:
            continue
    return results
