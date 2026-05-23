"""spotlight.py – highlight secrets matching a pattern with context info."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional
import re


class SpotlightError(Exception):
    """Raised when a spotlight operation fails."""


@dataclass
class SpotlightMatch:
    environment: str
    key: str
    preview: str  # redacted snippet showing why it matched

    def to_dict(self) -> dict:
        return {
            "environment": self.environment,
            "key": self.key,
            "preview": self.preview,
        }


@dataclass
class SpotlightResult:
    pattern: str
    matches: List[SpotlightMatch] = field(default_factory=list)
    total: int = 0

    def to_dict(self) -> dict:
        return {
            "pattern": self.pattern,
            "matches": [m.to_dict() for m in self.matches],
            "total": self.total,
        }


def _safe_preview(value: str, pattern: str, window: int = 6) -> str:
    """Return a redacted preview that shows *why* the value matched."""
    try:
        m = re.search(pattern, value, re.IGNORECASE)
    except re.error:
        return "<invalid pattern>"
    if m is None:
        return "<no match>"
    start = max(0, m.start() - window)
    end = min(len(value), m.end() + window)
    snippet = value[start:end]
    # Redact all but the matched portion
    before = "*" * min(window, m.start())
    matched = snippet[m.start() - start: m.end() - start]
    after = "*" * min(window, len(value) - m.end())
    return f"{before}{matched}{after}"


def spotlight_secrets(
    vault,
    pattern: str,
    environment: Optional[str] = None,
) -> SpotlightResult:
    """Search secret *values* for *pattern* and return highlighted matches.

    Unlike :func:`envault.search.search_secrets` which searches keys,
    ``spotlight_secrets`` inspects decrypted values.
    """
    try:
        compiled = re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        raise SpotlightError(f"Invalid pattern {pattern!r}: {exc}") from exc

    result = SpotlightResult(pattern=pattern)
    envs = [environment] if environment else vault.list_environments()

    for env in envs:
        for key in vault.list_secrets(env):
            entry = vault.get_secret(env, key)
            if entry is None:
                continue
            try:
                value = entry.decrypt()
            except Exception:
                continue
            if compiled.search(value):
                preview = _safe_preview(value, pattern)
                result.matches.append(SpotlightMatch(env, key, preview))

    result.total = len(result.matches)
    return result
