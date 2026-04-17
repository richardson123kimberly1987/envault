"""Pin secrets to specific versions, preventing accidental overwrites."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


class PinError(Exception):
    """Raised when a pin operation fails."""


@dataclass
class PinResult:
    key: str
    environment: str
    pinned: bool
    version: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "environment": self.environment,
            "pinned": self.pinned,
            "version": self.version,
        }


def pin_secret(vault, environment: str, key: str, version: str) -> PinResult:
    """Pin a secret to a specific version string."""
    entry = vault.get_secret(environment, key)
    if entry is None:
        raise PinError(f"Secret '{key}' not found in environment '{environment}'")
    data = entry.to_dict()
    data.setdefault("meta", {})
    data["meta"]["pinned_version"] = version
    data["meta"]["pinned"] = True
    vault.set_secret(environment, key, data["value"], data["meta"])
    return PinResult(key=key, environment=environment, pinned=True, version=version)


def unpin_secret(vault, environment: str, key: str) -> PinResult:
    """Remove the pin from a secret."""
    entry = vault.get_secret(environment, key)
    if entry is None:
        raise PinError(f"Secret '{key}' not found in environment '{environment}'")
    data = entry.to_dict()
    meta = data.get("meta", {})
    meta.pop("pinned_version", None)
    meta.pop("pinned", None)
    vault.set_secret(environment, key, data["value"], meta)
    return PinResult(key=key, environment=environment, pinned=False, version=None)


def list_pinned(vault, environment: str) -> list[PinResult]:
    """Return all pinned secrets in an environment."""
    results = []
    for key in vault.list_secrets(environment):
        entry = vault.get_secret(environment, key)
        if entry is None:
            continue
        d = entry.to_dict()
        meta = d.get("meta", {})
        if meta.get("pinned"):
            results.append(
                PinResult(
                    key=key,
                    environment=environment,
                    pinned=True,
                    version=meta.get("pinned_version"),
                )
            )
    return results
