"""Compliance checking for secrets in the vault.

Provides functions to evaluate secrets against configurable compliance
policies (e.g. minimum length, character requirements, rotation age).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# Built-in compliance rule identifiers
COMPLIANCE_RULES: list[str] = [
    "min_length",
    "requires_uppercase",
    "requires_digit",
    "requires_special",
    "max_age_days",
    "no_common_patterns",
]

# Patterns considered weak / non-compliant
_COMMON_PATTERNS = [
    re.compile(r"^(password|secret|changeme|12345|admin|letmein)", re.IGNORECASE),
    re.compile(r"^(.)(\1+)$"),  # single repeated character
]


class ComplianceError(Exception):
    """Raised when a compliance operation fails unexpectedly."""


@dataclass
class ComplianceViolation:
    """A single rule violation for a secret."""

    rule: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {"rule": self.rule, "message": self.message}


@dataclass
class ComplianceResult:
    """Aggregated compliance result for a secret."""

    secret_name: str
    environment: str
    passed: bool
    violations: list[ComplianceViolation] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "secret_name": self.secret_name,
            "environment": self.environment,
            "passed": self.passed,
            "violations": [v.to_dict() for v in self.violations],
        }


def _check_secret(
    name: str,
    value: str,
    entry_meta: dict[str, Any],
    rules: dict[str, Any],
) -> list[ComplianceViolation]:
    """Evaluate *value* against *rules* and return any violations."""
    violations: list[ComplianceViolation] = []

    min_length: int = int(rules.get("min_length", 8))
    if len(value) < min_length:
        violations.append(
            ComplianceViolation(
                rule="min_length",
                message=f"Value length {len(value)} is below minimum {min_length}.",
            )
        )

    if rules.get("requires_uppercase", False) and not any(c.isupper() for c in value):
        violations.append(
            ComplianceViolation(
                rule="requires_uppercase",
                message="Value must contain at least one uppercase letter.",
            )
        )

    if rules.get("requires_digit", False) and not any(c.isdigit() for c in value):
        violations.append(
            ComplianceViolation(
                rule="requires_digit",
                message="Value must contain at least one digit.",
            )
        )

    if rules.get("requires_special", False):
        if not re.search(r"[^A-Za-z0-9]", value):
            violations.append(
                ComplianceViolation(
                    rule="requires_special",
                    message="Value must contain at least one special character.",
                )
            )

    max_age: int | None = rules.get("max_age_days")
    if max_age is not None:
        updated_at_str: str | None = entry_meta.get("updated_at")
        if updated_at_str:
            try:
                updated_at = datetime.fromisoformat(updated_at_str)
                if updated_at.tzinfo is None:
                    updated_at = updated_at.replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - updated_at).days
                if age_days > max_age:
                    violations.append(
                        ComplianceViolation(
                            rule="max_age_days",
                            message=(
                                f"Secret is {age_days} days old; "
                                f"maximum allowed is {max_age} days."
                            ),
                        )
                    )
            except ValueError:
                pass  # unparseable date — skip age check

    if rules.get("no_common_patterns", True):
        for pattern in _COMMON_PATTERNS:
            if pattern.search(value):
                violations.append(
                    ComplianceViolation(
                        rule="no_common_patterns",
                        message="Value matches a known weak/common pattern.",
                    )
                )
                break

    return violations


def check_compliance(
    vault: Any,
    environment: str,
    passphrase: str,
    rules: dict[str, Any] | None = None,
) -> list[ComplianceResult]:
    """Check all secrets in *environment* against *rules*.

    Parameters
    ----------
    vault:
        A ``Vault`` instance (or compatible duck-type).
    environment:
        The environment name to inspect.
    passphrase:
        Passphrase used to decrypt secret values.
    rules:
        Mapping of rule name → parameter.  Defaults apply when omitted.

    Returns
    -------
    list[ComplianceResult]
        One result per secret, ordered by secret name.
    """
    if rules is None:
        rules = {}

    results: list[ComplianceResult] = []

    try:
        secret_names: list[str] = vault.list_secrets(environment)
    except Exception as exc:  # pragma: no cover
        raise ComplianceError(f"Failed to list secrets: {exc}") from exc

    for name in sorted(secret_names):
        entry = vault.get_secret(environment, name)
        if entry is None:
            continue

        try:
            entry_dict: dict[str, Any] = entry.to_dict()
            value: str = vault.decrypt(entry_dict.get("value", ""), passphrase)
        except Exception as exc:
            raise ComplianceError(
                f"Failed to decrypt secret '{name}' in '{environment}': {exc}"
            ) from exc

        violations = _check_secret(name, value, entry_dict, rules)
        results.append(
            ComplianceResult(
                secret_name=name,
                environment=environment,
                passed=len(violations) == 0,
                violations=violations,
            )
        )

    return results
