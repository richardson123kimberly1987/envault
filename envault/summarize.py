"""Summarize secrets in a vault environment."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class SummarizeError(Exception):
    """Raised when summarization fails."""


@dataclass
class SummaryResult:
    environment: str
    total: int
    has_expiry: int
    locked: int
    tagged: int
    secret_names: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "environment": self.environment,
            "total": self.total,
            "has_expiry": self.has_expiry,
            "locked": self.locked,
            "tagged": self.tagged,
            "secret_names": self.secret_names,
        }


def summarize_environment(vault: Any, environment: str) -> SummaryResult:
    """Return a summary of all secrets in *environment*."""
    if environment not in vault.list_environments():
        raise SummarizeError(f"Environment '{environment}' not found.")

    names = vault.list_secrets(environment)
    total = len(names)
    has_expiry = 0
    locked = 0
    tagged = 0

    for name in names:
        entry = vault.get_secret(environment, name)
        if entry is None:
            continue
        d = entry.to_dict()
        if d.get("expires_at"):
            has_expiry += 1
        if d.get("locked"):
            locked += 1
        if d.get("tags"):
            tagged += 1

    return SummaryResult(
        environment=environment,
        total=total,
        has_expiry=has_expiry,
        locked=locked,
        tagged=tagged,
        secret_names=list(names),
    )


def summarize_all(vault: Any) -> list[SummaryResult]:
    """Return summaries for every environment in the vault."""
    return [summarize_environment(vault, env) for env in vault.list_environments()]
