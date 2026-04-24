"""Secret grouping — organise secrets into named groups within an environment."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

GROUP_META_KEY = "__groups__"


class GroupError(Exception):
    """Raised when a group operation fails."""


@dataclass
class GroupResult:
    group: str
    secret: str
    environment: str
    action: str  # 'added' | 'removed' | 'listed'
    members: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "group": self.group,
            "secret": self.secret,
            "environment": self.environment,
            "action": self.action,
            "members": self.members,
        }


def _load_groups(vault, environment: str) -> dict:
    """Return the groups mapping stored as a special meta-secret."""
    entry = vault.get_secret(GROUP_META_KEY, environment)
    if entry is None:
        return {}
    import json
    try:
        return json.loads(entry.to_dict().get("value", "{}"))
    except (ValueError, KeyError):
        return {}


def _save_groups(vault, environment: str, groups: dict) -> None:
    import json
    vault.set_secret(GROUP_META_KEY, json.dumps(groups), environment)
    vault.save()


def add_to_group(vault, group: str, secret: str, environment: str) -> GroupResult:
    """Add *secret* to *group* in *environment*."""
    if vault.get_secret(secret, environment) is None:
        raise GroupError(f"Secret '{secret}' not found in environment '{environment}'.")
    groups = _load_groups(vault, environment)
    members: List[str] = groups.get(group, [])
    if secret not in members:
        members.append(secret)
    groups[group] = members
    _save_groups(vault, environment, groups)
    return GroupResult(group=group, secret=secret, environment=environment,
                       action="added", members=members)


def remove_from_group(vault, group: str, secret: str, environment: str) -> GroupResult:
    """Remove *secret* from *group* in *environment*."""
    groups = _load_groups(vault, environment)
    members: List[str] = groups.get(group, [])
    if secret not in members:
        raise GroupError(f"Secret '{secret}' is not a member of group '{group}'.")
    members.remove(secret)
    groups[group] = members
    _save_groups(vault, environment, groups)
    return GroupResult(group=group, secret=secret, environment=environment,
                       action="removed", members=members)


def list_group(vault, group: str, environment: str) -> GroupResult:
    """Return all secrets that belong to *group* in *environment*."""
    groups = _load_groups(vault, environment)
    members = groups.get(group, [])
    return GroupResult(group=group, secret="", environment=environment,
                       action="listed", members=members)
