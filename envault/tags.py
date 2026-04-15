"""Tag management for secrets — allows grouping and filtering secrets by tags."""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, List, Optional

if TYPE_CHECKING:
    from envault.vault import Vault


class TagError(Exception):
    """Raised when a tagging operation fails."""


class TagResult:
    """Holds a secret key, its environment, and matched tags."""

    def __init__(self, environment: str, key: str, tags: List[str]) -> None:
        self.environment = environment
        self.key = key
        self.tags = tags

    def to_dict(self) -> Dict:
        return {"environment": self.environment, "key": self.key, "tags": self.tags}


def add_tag(vault: "Vault", environment: str, key: str, tag: str) -> None:
    """Add a tag to a secret. Raises TagError if the secret does not exist."""
    entry = vault.get_secret(environment, key)
    if entry is None:
        raise TagError(f"Secret '{key}' not found in environment '{environment}'.")
    tags: List[str] = entry.to_dict().get("tags", [])
    if tag not in tags:
        tags.append(tag)
    entry_dict = entry.to_dict()
    entry_dict["tags"] = tags
    # Persist via vault set_secret using existing value
    vault.set_secret(environment, key, entry_dict["value"], tags=tags)


def remove_tag(vault: "Vault", environment: str, key: str, tag: str) -> None:
    """Remove a tag from a secret. Raises TagError if the secret does not exist."""
    entry = vault.get_secret(environment, key)
    if entry is None:
        raise TagError(f"Secret '{key}' not found in environment '{environment}'.")
    entry_dict = entry.to_dict()
    tags: List[str] = entry_dict.get("tags", [])
    tags = [t for t in tags if t != tag]
    vault.set_secret(environment, key, entry_dict["value"], tags=tags)


def list_by_tag(
    vault: "Vault", tag: str, environment: Optional[str] = None
) -> List[TagResult]:
    """Return all secrets that carry *tag*, optionally filtered to one environment."""
    results: List[TagResult] = []
    envs = [environment] if environment else vault.list_environments()
    for env in envs:
        for key in vault.list_secrets(env):
            entry = vault.get_secret(env, key)
            if entry is None:
                continue
            tags: List[str] = entry.to_dict().get("tags", [])
            if tag in tags:
                results.append(TagResult(env, key, tags))
    return results
