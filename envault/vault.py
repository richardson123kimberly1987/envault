"""Vault module for storing and retrieving encrypted secrets."""

import json
import os
from pathlib import Path
from typing import Dict, Optional

from envault.crypto import decrypt, encrypt

DEFAULT_VAULT_PATH = Path(".envault")


class VaultError(Exception):
    """Raised when a vault operation fails."""


class Vault:
    """Manages an encrypted vault of environment variable secrets."""

    def __init__(self, path: Path = DEFAULT_VAULT_PATH, passphrase: str = "") -> None:
        self.path = Path(path)
        self.passphrase = passphrase
        self._secrets: Dict[str, Dict[str, str]] = {}

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Load and decrypt the vault from disk."""
        if not self.path.exists():
            self._secrets = {}
            return
        try:
            raw = self.path.read_text(encoding="utf-8")
            plaintext = decrypt(raw, self.passphrase)
            self._secrets = json.loads(plaintext)
        except Exception as exc:
            raise VaultError(f"Failed to load vault: {exc}") from exc

    def save(self) -> None:
        """Encrypt and persist the vault to disk."""
        try:
            plaintext = json.dumps(self._secrets, indent=2)
            ciphertext = encrypt(plaintext, self.passphrase)
            self.path.write_text(ciphertext, encoding="utf-8")
        except Exception as exc:
            raise VaultError(f"Failed to save vault: {exc}") from exc

    # ------------------------------------------------------------------
    # Secret management
    # ------------------------------------------------------------------

    def set_secret(self, env: str, key: str, value: str) -> None:
        """Store a secret for a given environment."""
        self._secrets.setdefault(env, {})[key] = value

    def get_secret(self, env: str, key: str) -> Optional[str]:
        """Retrieve a secret for a given environment."""
        return self._secrets.get(env, {}).get(key)

    def delete_secret(self, env: str, key: str) -> bool:
        """Delete a secret; returns True if it existed."""
        env_secrets = self._secrets.get(env, {})
        if key in env_secrets:
            del env_secrets[key]
            return True
        return False

    def list_keys(self, env: str) -> list:
        """Return all secret keys for a given environment."""
        return list(self._secrets.get(env, {}).keys())

    def list_envs(self) -> list:
        """Return all environment names stored in the vault."""
        return list(self._secrets.keys())

    def export_env(self, env: str) -> Dict[str, str]:
        """Return a copy of all secrets for a given environment."""
        return dict(self._secrets.get(env, {}))
