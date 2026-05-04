"""Format secrets values: uppercase, lowercase, strip, truncate, etc."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

FORMAT_RULES = ["uppercase", "lowercase", "strip", "truncate", "capitalize"]


class FormatError(Exception):
    """Raised when formatting fails."""


@dataclass
class FormatResult:
    secret: str
    environment: str
    original: str
    formatted: str
    rules_applied: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "secret": self.secret,
            "environment": self.environment,
            "original": self.original,
            "formatted": self.formatted,
            "rules_applied": self.rules_applied,
        }


def _apply_format(value: str, rules: list[str], truncate_len: int = 64) -> tuple[str, list[str]]:
    applied: list[str] = []
    result = value
    for rule in rules:
        if rule == "uppercase":
            result = result.upper()
            applied.append(rule)
        elif rule == "lowercase":
            result = result.lower()
            applied.append(rule)
        elif rule == "strip":
            result = result.strip()
            applied.append(rule)
        elif rule == "capitalize":
            result = result.capitalize()
            applied.append(rule)
        elif rule == "truncate":
            result = result[:truncate_len]
            applied.append(rule)
        else:
            raise FormatError(f"Unknown format rule: {rule!r}. Valid rules: {FORMAT_RULES}")
    return result, applied


def format_secret(
    vault: Any,
    environment: str,
    secret: str,
    rules: list[str],
    truncate_len: int = 64,
) -> FormatResult:
    """Apply formatting rules to a secret's value and persist the change."""
    entry = vault.get_secret(environment, secret)
    if entry is None:
        raise FormatError(f"Secret {secret!r} not found in environment {environment!r}")
    if not rules:
        raise FormatError("At least one format rule must be specified")
    original = entry.decrypt()
    formatted, applied = _apply_format(original, rules, truncate_len)
    entry.update_value(formatted)
    vault.save()
    return FormatResult(
        secret=secret,
        environment=environment,
        original=original,
        formatted=formatted,
        rules_applied=applied,
    )


def format_all(
    vault: Any,
    environment: str,
    rules: list[str],
    truncate_len: int = 64,
) -> list[FormatResult]:
    """Apply formatting rules to every secret in an environment."""
    results = []
    for name in vault.list_secrets(environment):
        results.append(format_secret(vault, environment, name, rules, truncate_len))
    return results
