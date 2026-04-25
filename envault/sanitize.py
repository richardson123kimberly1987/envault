"""Sanitize secret values by stripping dangerous characters or patterns."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
import re


class SanitizeError(Exception):
    """Raised when sanitization fails."""


# Built-in sanitization rules
SANITIZE_RULES: dict[str, str] = {
    "strip_whitespace": "Remove leading/trailing whitespace",
    "strip_newlines": "Remove newline characters",
    "strip_null_bytes": "Remove null bytes",
    "strip_ansi": "Remove ANSI escape sequences",
    "strip_control": "Remove ASCII control characters",
}

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[mGKHF]")
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


@dataclass
class SanitizeResult:
    key: str
    environment: str
    original: str
    sanitized: str
    rules_applied: list[str]
    changed: bool

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "environment": self.environment,
            "original": self.original,
            "sanitized": self.sanitized,
            "rules_applied": self.rules_applied,
            "changed": self.changed,
        }


def _apply_rules(value: str, rules: list[str]) -> tuple[str, list[str]]:
    applied: list[str] = []
    result = value

    for rule in rules:
        if rule not in SANITIZE_RULES:
            raise SanitizeError(f"Unknown sanitization rule: {rule!r}")
        before = result
        if rule == "strip_whitespace":
            result = result.strip()
        elif rule == "strip_newlines":
            result = result.replace("\n", "").replace("\r", "")
        elif rule == "strip_null_bytes":
            result = result.replace("\x00", "")
        elif rule == "strip_ansi":
            result = _ANSI_ESCAPE.sub("", result)
        elif rule == "strip_control":
            result = _CONTROL_CHARS.sub("", result)
        if result != before:
            applied.append(rule)

    return result, applied


def sanitize_secret(
    vault,
    key: str,
    environment: str,
    rules: Optional[list[str]] = None,
) -> SanitizeResult:
    """Apply sanitization rules to a secret value and persist the result."""
    if rules is None:
        rules = ["strip_whitespace", "strip_newlines", "strip_null_bytes"]

    entry = vault.get_secret(key, environment)
    if entry is None:
        raise SanitizeError(f"Secret {key!r} not found in environment {environment!r}")

    raw = entry.to_dict().get("value", "")
    sanitized, applied = _apply_rules(raw, rules)
    changed = sanitized != raw

    if changed:
        vault.set_secret(key, sanitized, environment)

    return SanitizeResult(
        key=key,
        environment=environment,
        original=raw,
        sanitized=sanitized,
        rules_applied=applied,
        changed=changed,
    )


def sanitize_all(
    vault,
    environment: str,
    rules: Optional[list[str]] = None,
) -> list[SanitizeResult]:
    """Sanitize all secrets in an environment."""
    results = []
    for key in vault.list_secrets(environment):
        results.append(sanitize_secret(vault, key, environment, rules))
    return results
