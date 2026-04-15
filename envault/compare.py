"""Compare secret values across environments."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

CompareError = type("CompareError", (Exception,), {})


@dataclass
class CompareResult:
    key: str
    environments: Dict[str, Optional[str]]
    status: str  # 'match', 'mismatch', 'missing'

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "environments": self.environments,
            "status": self.status,
        }


def compare_secret(
    vault,
    key: str,
    environments: List[str],
    passphrase: str,
) -> CompareResult:
    """Compare a single secret's value across the given environments."""
    if not environments or len(environments) < 2:
        raise CompareError("At least two environments are required for comparison.")

    values: Dict[str, Optional[str]] = {}
    for env in environments:
        entry = vault.get_secret(key, env)
        if entry is None:
            values[env] = None
        else:
            try:
                from envault.crypto import decrypt
                values[env] = decrypt(entry.encrypted_value, passphrase)
            except Exception:
                values[env] = None

    unique = set(v for v in values.values() if v is not None)
    missing = any(v is None for v in values.values())

    if missing:
        status = "missing"
    elif len(unique) == 1:
        status = "match"
    else:
        status = "mismatch"

    return CompareResult(key=key, environments=values, status=status)


def compare_all(
    vault,
    environments: List[str],
    passphrase: str,
) -> List[CompareResult]:
    """Compare all secrets that appear in at least one of the given environments."""
    if not environments or len(environments) < 2:
        raise CompareError("At least two environments are required for comparison.")

    all_keys: set = set()
    for env in environments:
        all_keys.update(vault.list_secrets(env))

    return [
        compare_secret(vault, key, environments, passphrase)
        for key in sorted(all_keys)
    ]
