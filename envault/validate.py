"""Secret value validation rules for envault."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional
import re


class ValidateError(Exception):
    """Raised when validation configuration is invalid."""


VALIDATE_RULES = ["min_length", "max_length", "regex", "no_spaces", "not_empty"]


@dataclass
class ValidationIssue:
    key: str
    environment: str
    rule: str
    message: str

    def to_dict(self) -> dict:
        return {"key": self.key, "environment": self.environment,
                "rule": self.rule, "message": self.message}


@dataclass
class ValidationResult:
    issues: List[ValidationIssue] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return len(self.issues) == 0

    def to_dict(self) -> dict:
        return {"passed": self.passed, "issues": [i.to_dict() for i in self.issues]}


def validate_secrets(
    vault,
    environment: str,
    min_length: Optional[int] = None,
    max_length: Optional[int] = None,
    regex: Optional[str] = None,
    no_spaces: bool = False,
    not_empty: bool = True,
) -> ValidationResult:
    """Validate all secrets in an environment against the given rules."""
    if regex is not None:
        try:
            pattern = re.compile(regex)
        except re.error as exc:
            raise ValidateError(f"Invalid regex pattern: {exc}") from exc
    else:
        pattern = None

    issues: List[ValidationIssue] = []

    for key in vault.list_secrets(environment):
        entry = vault.get_secret(environment, key)
        if entry is None:
            continue
        value: str = entry.to_dict().get("value", "")

        if not_empty and value == "":
            issues.append(ValidationIssue(key, environment, "not_empty", f"'{key}' is empty."))
            continue

        if min_length is not None and len(value) < min_length:
            issues.append(ValidationIssue(key, environment, "min_length",
                f"'{key}' length {len(value)} < min {min_length}."))

        if max_length is not None and len(value) > max_length:
            issues.append(ValidationIssue(key, environment, "max_length",
                f"'{key}' length {len(value)} > max {max_length}."))

        if no_spaces and " " in value:
            issues.append(ValidationIssue(key, environment, "no_spaces",
                f"'{key}' contains spaces."))

        if pattern is not None and not pattern.search(value):
            issues.append(ValidationIssue(key, environment, "regex",
                f"'{key}' does not match pattern '{regex}'."))

    return ValidationResult(issues=issues)
