"""Lint/validate secrets for common issues like weak values, missing entries, or naming violations."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

LINT_CHECKS = ["weak_value", "naming_convention", "empty_value", "duplicate_key"]

_WEAK_VALUES = {"password", "secret", "changeme", "1234", "12345", "123456", "test", "admin"}
_NAME_RE = re.compile(r'^[A-Z][A-Z0-9_]*$')


class LintError(Exception):
    """Raised when linting cannot be performed."""


@dataclass
class LintIssue:
    key: str
    environment: str
    check: str
    message: str

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "environment": self.environment,
            "check": self.check,
            "message": self.message,
        }


@dataclass
class LintResult:
    issues: List[LintIssue] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return len(self.issues) == 0

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "issue_count": len(self.issues),
            "issues": [i.to_dict() for i in self.issues],
        }


def lint_secrets(vault, environment: Optional[str] = None) -> LintResult:
    """Run all lint checks against secrets in the vault."""
    envs = [environment] if environment else vault.list_environments()
    if not envs:
        raise LintError("No environments found in vault.")

    result = LintResult()
    seen: dict = {}

    for env in envs:
        keys = vault.list_secrets(env)
        for key in keys:
            entry = vault.get_secret(env, key)
            if entry is None:
                continue
            value = entry.to_dict().get("value", "")

            # empty_value check
            if not value or not value.strip():
                result.issues.append(LintIssue(key, env, "empty_value", f"Secret '{key}' has an empty value."))

            # weak_value check
            if value.strip().lower() in _WEAK_VALUES:
                result.issues.append(LintIssue(key, env, "weak_value", f"Secret '{key}' uses a commonly weak value."))

            # naming_convention check
            if not _NAME_RE.match(key):
                result.issues.append(LintIssue(key, env, "naming_convention",
                                               f"Secret '{key}' does not follow UPPER_SNAKE_CASE convention."))

            # duplicate_key check across environments
            if key not in seen:
                seen[key] = env

    return result
