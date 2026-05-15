"""Shadow copy management for secrets — keeps a hidden copy of previous values."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class ShadowError(Exception):
    """Raised when a shadow operation fails."""


@dataclass
class ShadowResult:
    secret: str
    environment: str
    previous_value: str | None
    current_value: str
    had_shadow: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "secret": self.secret,
            "environment": self.environment,
            "previous_value": self.previous_value,
            "current_value": self.current_value,
            "had_shadow": self.had_shadow,
        }


_SHADOW_META_KEY = "__shadow__"


def _get_entry_or_raise(vault: Any, environment: str, secret: str) -> Any:
    entry = vault.get_secret(environment, secret)
    if entry is None:
        raise ShadowError(f"Secret '{secret}' not found in environment '{environment}'")
    return entry


def capture_shadow(vault: Any, environment: str, secret: str) -> ShadowResult:
    """Store the current value as a shadow (previous) copy before it changes."""
    entry = _get_entry_or_raise(vault, environment, secret)
    current = entry.decrypt()
    meta = entry.to_dict().get("metadata", {})
    previous = meta.get(_SHADOW_META_KEY)
    had_shadow = previous is not None
    entry.update_value(
        current,
        metadata={**meta, _SHADOW_META_KEY: current},
    )
    vault.save()
    return ShadowResult(
        secret=secret,
        environment=environment,
        previous_value=previous,
        current_value=current,
        had_shadow=had_shadow,
    )


def get_shadow(vault: Any, environment: str, secret: str) -> ShadowResult:
    """Retrieve the shadow (previous) value for a secret."""
    entry = _get_entry_or_raise(vault, environment, secret)
    current = entry.decrypt()
    meta = entry.to_dict().get("metadata", {})
    previous = meta.get(_SHADOW_META_KEY)
    return ShadowResult(
        secret=secret,
        environment=environment,
        previous_value=previous,
        current_value=current,
        had_shadow=previous is not None,
    )


def clear_shadow(vault: Any, environment: str, secret: str) -> ShadowResult:
    """Remove the shadow copy from a secret's metadata."""
    entry = _get_entry_or_raise(vault, environment, secret)
    current = entry.decrypt()
    meta = dict(entry.to_dict().get("metadata", {}))
    previous = meta.pop(_SHADOW_META_KEY, None)
    entry.update_value(current, metadata=meta)
    vault.save()
    return ShadowResult(
        secret=secret,
        environment=environment,
        previous_value=previous,
        current_value=current,
        had_shadow=previous is not None,
    )
