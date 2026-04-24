"""Secret resolution with fallback chain across environments."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


class ResolveError(Exception):
    """Raised when secret resolution fails."""


@dataclass
class ResolveResult:
    key: str
    value: Optional[str]
    resolved_env: Optional[str]
    chain: list[str] = field(default_factory=list)
    found: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "value": self.value,
            "resolved_env": self.resolved_env,
            "chain": self.chain,
            "found": self.found,
        }


def resolve_secret(
    vault: Any,
    key: str,
    env_chain: list[str],
    passphrase: str,
) -> ResolveResult:
    """Resolve a secret by walking an ordered chain of environments.

    Returns the first environment in *env_chain* that contains *key*.
    If no environment has the key, ``found`` is False and ``value`` is None.
    """
    if not env_chain:
        raise ResolveError("env_chain must contain at least one environment")

    for env in env_chain:
        entry = vault.get_secret(env, key)
        if entry is not None:
            try:
                value = entry.decrypt(passphrase)
            except Exception as exc:  # pragma: no cover
                raise ResolveError(
                    f"Failed to decrypt '{key}' in env '{env}': {exc}"
                ) from exc
            return ResolveResult(
                key=key,
                value=value,
                resolved_env=env,
                chain=list(env_chain),
                found=True,
            )

    return ResolveResult(
        key=key,
        value=None,
        resolved_env=None,
        chain=list(env_chain),
        found=False,
    )


def resolve_all(
    vault: Any,
    env_chain: list[str],
    passphrase: str,
) -> list[ResolveResult]:
    """Resolve every key visible across *env_chain* using fallback semantics.

    All keys present in any environment in the chain are resolved; each key
    uses the first environment in the chain that defines it.
    """
    if not env_chain:
        raise ResolveError("env_chain must contain at least one environment")

    all_keys: set[str] = set()
    for env in env_chain:
        all_keys.update(vault.list_secrets(env))

    return [
        resolve_secret(vault, key, env_chain, passphrase)
        for key in sorted(all_keys)
    ]
