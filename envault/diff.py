"""Diff utilities for comparing secrets across environments."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional


class DiffError(Exception):
    """Raised when a diff operation fails."""


@dataclass
class SecretDiff:
    """Represents a single secret difference between two environments."""

    key: str
    status: str  # 'added', 'removed', 'changed', 'unchanged'
    left_value: Optional[str] = None
    right_value: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "status": self.status,
            "left_value": self.left_value,
            "right_value": self.right_value,
        }


def diff_environments(
    vault,
    left_env: str,
    right_env: str,
    *,
    show_values: bool = False,
) -> List[SecretDiff]:
    """Compare secrets between two environments in a vault.

    Args:
        vault: A Vault instance.
        left_env: Name of the base environment.
        right_env: Name of the environment to compare against.
        show_values: If True, include plaintext values in the diff.

    Returns:
        A list of SecretDiff objects sorted by key.

    Raises:
        DiffError: If either environment does not exist in the vault.
    """
    available = vault.list_environments()
    if left_env not in available:
        raise DiffError(f"Environment '{left_env}' not found in vault.")
    if right_env not in available:
        raise DiffError(f"Environment '{right_env}' not found in vault.")

    left_secrets: Dict[str, str] = vault.list_secrets(left_env)
    right_secrets: Dict[str, str] = vault.list_secrets(right_env)

    all_keys = sorted(set(left_secrets) | set(right_secrets))
    results: List[SecretDiff] = []

    for key in all_keys:
        in_left = key in left_secrets
        in_right = key in right_secrets

        lv = left_secrets.get(key) if show_values else None
        rv = right_secrets.get(key) if show_values else None

        if in_left and not in_right:
            status = "removed"
        elif in_right and not in_left:
            status = "added"
        elif left_secrets[key] == right_secrets[key]:
            status = "unchanged"
        else:
            status = "changed"

        results.append(SecretDiff(key=key, status=status, left_value=lv, right_value=rv))

    return results


def format_diff(diffs: List[SecretDiff], *, show_values: bool = False) -> str:
    """Render a list of SecretDiff objects as a human-readable string."""
    if not diffs:
        return "No differences found."

    symbols = {"added": "+", "removed": "-", "changed": "~", "unchanged": " "}
    lines = []
    for d in diffs:
        sym = symbols.get(d.status, "?")
        if show_values and d.status == "changed":
            lines.append(f"{sym} {d.key}: {d.left_value!r} -> {d.right_value!r}")
        else:
            lines.append(f"{sym} {d.key}")
    return "\n".join(lines)
