"""Access control for envault secrets — role-based permissions per environment."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

ACCESS_ROLES = ("read", "write", "admin")

_ROLE_HIERARCHY = {"read": 0, "write": 1, "admin": 2}


class AccessError(Exception):
    """Raised when an access control operation fails."""


@dataclass
class AccessRule:
    identity: str
    role: str
    environment: Optional[str] = None  # None means all environments

    def __post_init__(self) -> None:
        if self.role not in ACCESS_ROLES:
            raise AccessError(f"Invalid role '{self.role}'. Must be one of {ACCESS_ROLES}.")

    def to_dict(self) -> dict:
        return {
            "identity": self.identity,
            "role": self.role,
            "environment": self.environment,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AccessRule":
        return cls(
            identity=data["identity"],
            role=data["role"],
            environment=data.get("environment"),
        )


@dataclass
class AccessPolicy:
    rules: List[AccessRule] = field(default_factory=list)

    def add_rule(self, identity: str, role: str, environment: Optional[str] = None) -> AccessRule:
        rule = AccessRule(identity=identity, role=role, environment=environment)
        # Replace existing rule for same identity+environment
        self.rules = [
            r for r in self.rules
            if not (r.identity == identity and r.environment == environment)
        ]
        self.rules.append(rule)
        return rule

    def remove_rule(self, identity: str, environment: Optional[str] = None) -> bool:
        before = len(self.rules)
        self.rules = [
            r for r in self.rules
            if not (r.identity == identity and r.environment == environment)
        ]
        return len(self.rules) < before

    def get_role(self, identity: str, environment: Optional[str] = None) -> Optional[str]:
        """Return the most permissive role for identity in the given environment."""
        best: Optional[str] = None
        for rule in self.rules:
            if rule.identity != identity:
                continue
            if rule.environment is not None and rule.environment != environment:
                continue
            if best is None or _ROLE_HIERARCHY[rule.role] > _ROLE_HIERARCHY[best]:
                best = rule.role
        return best

    def can(self, identity: str, action: str, environment: Optional[str] = None) -> bool:
        if action not in ACCESS_ROLES:
            raise AccessError(f"Unknown action '{action}'.")
        role = self.get_role(identity, environment)
        if role is None:
            return False
        return _ROLE_HIERARCHY[role] >= _ROLE_HIERARCHY[action]

    def to_dict(self) -> dict:
        return {"rules": [r.to_dict() for r in self.rules]}

    @classmethod
    def from_dict(cls, data: dict) -> "AccessPolicy":
        return cls(rules=[AccessRule.from_dict(r) for r in data.get("rules", [])])
