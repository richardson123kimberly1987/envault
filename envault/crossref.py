"""Cross-reference detection for secrets that share values across environments."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


class CrossRefError(Exception):
    """Raised when cross-reference operations fail."""


@dataclass
class CrossRefMatch:
    """A pair of (env, key) locations that share the same plaintext value."""

    key: str
    environments: List[str]

    def to_dict(self) -> dict:
        return {"key": self.key, "environments": self.environments}


@dataclass
class CrossRefResult:
    """Result of a cross-reference scan."""

    matches: List[CrossRefMatch] = field(default_factory=list)
    scanned: int = 0

    def to_dict(self) -> dict:
        return {
            "scanned": self.scanned,
            "matches": [m.to_dict() for m in self.matches],
        }


def find_crossrefs(
    vault,
    environment: Optional[str] = None,
    passphrase: str = "",
) -> CrossRefResult:
    """Find secrets whose plaintext values appear in more than one environment.

    Args:
        vault: A Vault instance.
        environment: If given, only report matches that involve this environment.
        passphrase: Passphrase used to decrypt secret values.

    Returns:
        CrossRefResult listing every key whose value is shared across envs.
    """
    envs = vault.list_environments()
    # value -> {key -> [env, ...]}
    value_map: Dict[str, Dict[str, List[str]]] = {}
    scanned = 0

    for env in envs:
        for key in vault.list_secrets(env):
            entry = vault.get_secret(env, key)
            if entry is None:
                continue
            try:
                plaintext = entry.decrypt(passphrase)
            except Exception:
                continue
            scanned += 1
            value_map.setdefault(plaintext, {}).setdefault(key, []).append(env)

    matches: List[CrossRefMatch] = []
    for _val, key_envs in value_map.items():
        for key, env_list in key_envs.items():
            if len(env_list) < 2:
                continue
            if environment and environment not in env_list:
                continue
            matches.append(CrossRefMatch(key=key, environments=sorted(env_list)))

    matches.sort(key=lambda m: m.key)
    return CrossRefResult(matches=matches, scanned=scanned)
