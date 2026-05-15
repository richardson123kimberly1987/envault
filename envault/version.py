"""Version tracking for vault secrets — record and retrieve version numbers."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

VERSION_KEY = "_versions"


class VersionError(Exception):
    """Raised when a versioning operation fails."""


@dataclass
class VersionResult:
    secret: str
    environment: str
    version: int
    previous: Optional[int]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "secret": self.secret,
            "environment": self.environment,
            "version": self.version,
            "previous": self.previous,
        }


def _load_versions(vault: Any) -> Dict[str, Any]:
    raw = vault.get_secret("__meta__", VERSION_KEY)
    if raw is None:
        return {}
    import json
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return {}


def _save_versions(vault: Any, data: Dict[str, Any]) -> None:
    import json
    vault.set_secret("__meta__", VERSION_KEY, json.dumps(data))


def bump_version(vault: Any, environment: str, secret: str) -> VersionResult:
    """Increment the version counter for a secret in an environment."""
    entry = vault.get_secret(environment, secret)
    if entry is None:
        raise VersionError(f"Secret '{secret}' not found in environment '{environment}'.")

    versions = _load_versions(vault)
    key = f"{environment}/{secret}"
    previous = versions.get(key, 0)
    current = previous + 1
    versions[key] = current
    _save_versions(vault, versions)
    return VersionResult(secret=secret, environment=environment, version=current, previous=previous if previous else None)


def get_version(vault: Any, environment: str, secret: str) -> int:
    """Return the current version number for a secret (0 if never bumped)."""
    versions = _load_versions(vault)
    return versions.get(f"{environment}/{secret}", 0)


def list_versions(vault: Any, environment: str) -> List[Dict[str, Any]]:
    """List all versioned secrets in an environment."""
    versions = _load_versions(vault)
    prefix = f"{environment}/"
    return [
        {"secret": k[len(prefix):], "environment": environment, "version": v}
        for k, v in versions.items()
        if k.startswith(prefix)
    ]
