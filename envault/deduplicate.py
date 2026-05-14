"""Deduplication of secrets across environments."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple


class DeduplicateError(Exception):
    """Raised when deduplication fails."""


@dataclass
class DeduplicateResult:
    """Result of a deduplication scan."""
    duplicates: Dict[str, List[Tuple[str, str]]] = field(default_factory=dict)
    # Maps canonical value-hash -> list of (environment, key) pairs

    def to_dict(self) -> dict:
        return {
            "duplicates": {
                h: [(env, key) for env, key in pairs]
                for h, pairs in self.duplicates.items()
            },
            "total_groups": len(self.duplicates),
            "total_duplicates": sum(
                len(pairs) for pairs in self.duplicates.values()
            ),
        }


def find_duplicates(vault, passphrase: str) -> DeduplicateResult:
    """Scan all environments and group secrets that share the same plaintext value.

    Args:
        vault: A :class:`~envault.vault.Vault` instance.
        passphrase: Master passphrase used to decrypt secrets.

    Returns:
        A :class:`DeduplicateResult` containing groups of duplicate secrets.

    Raises:
        DeduplicateError: If decryption fails for any entry.
    """
    from envault.crypto import decrypt

    value_map: Dict[str, List[Tuple[str, str]]] = {}

    for env in vault.list_environments():
        for key in vault.list_secrets(env):
            entry = vault.get_secret(env, key)
            if entry is None:
                continue
            try:
                plaintext = decrypt(entry.to_dict()["value"], passphrase)
            except Exception as exc:
                raise DeduplicateError(
                    f"Failed to decrypt '{key}' in '{env}': {exc}"
                ) from exc
            value_map.setdefault(plaintext, []).append((env, key))

    duplicates = {
        val: pairs for val, pairs in value_map.items() if len(pairs) > 1
    }
    # Replace raw plaintext keys with short hashes to avoid leaking values
    import hashlib
    hashed: Dict[str, List[Tuple[str, str]]] = {}
    for plaintext, pairs in duplicates.items():
        h = hashlib.sha256(plaintext.encode()).hexdigest()[:16]
        hashed[h] = pairs

    return DeduplicateResult(duplicates=hashed)
