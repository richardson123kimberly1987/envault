"""Namespace support for grouping secrets under logical prefixes."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


class NamespaceError(Exception):
    """Raised when a namespace operation fails."""


@dataclass
class NamespaceResult:
    namespace: str
    secrets: List[str] = field(default_factory=list)
    action: str = ""

    def to_dict(self) -> dict:
        return {
            "namespace": self.namespace,
            "secrets": self.secrets,
            "action": self.action,
        }


def _validate_namespace(namespace: str) -> None:
    if not namespace or not namespace.replace("-", "").replace("_", "").isalnum():
        raise NamespaceError(
            f"Invalid namespace '{namespace}': use only alphanumeric characters, hyphens, and underscores."
        )


def list_in_namespace(vault, environment: str, namespace: str) -> NamespaceResult:
    """List all secrets whose keys start with the given namespace prefix."""
    _validate_namespace(namespace)
    prefix = f"{namespace}/"
    matched = [
        key for key in vault.list_secrets(environment)
        if key.startswith(prefix)
    ]
    return NamespaceResult(namespace=namespace, secrets=matched, action="list")


def move_to_namespace(
    vault,
    environment: str,
    key: str,
    namespace: str,
    overwrite: bool = False,
) -> NamespaceResult:
    """Move a secret into a namespace by renaming its key."""
    _validate_namespace(namespace)
    entry = vault.get_secret(environment, key)
    if entry is None:
        raise NamespaceError(f"Secret '{key}' not found in environment '{environment}'.")
    new_key = f"{namespace}/{key}"
    if vault.get_secret(environment, new_key) is not None and not overwrite:
        raise NamespaceError(
            f"Secret '{new_key}' already exists. Use overwrite=True to replace it."
        )
    vault.set_secret(environment, new_key, entry.to_dict()["value"])
    vault.delete_secret(environment, key)
    vault.save()
    return NamespaceResult(namespace=namespace, secrets=[new_key], action="move")


def remove_from_namespace(
    vault,
    environment: str,
    key: str,
    namespace: Optional[str] = None,
) -> NamespaceResult:
    """Strip the namespace prefix from a secret key, moving it to the root."""
    if "/" not in key:
        raise NamespaceError(f"Secret '{key}' does not appear to be in a namespace.")
    ns, bare_key = key.split("/", 1)
    if namespace is not None and ns != namespace:
        raise NamespaceError(
            f"Secret '{key}' is in namespace '{ns}', not '{namespace}'."
        )
    entry = vault.get_secret(environment, key)
    if entry is None:
        raise NamespaceError(f"Secret '{key}' not found in environment '{environment}'.")
    vault.set_secret(environment, bare_key, entry.to_dict()["value"])
    vault.delete_secret(environment, key)
    vault.save()
    return NamespaceResult(namespace=ns, secrets=[bare_key], action="remove")
