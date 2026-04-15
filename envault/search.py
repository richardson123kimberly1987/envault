"""Search and filter secrets across environments."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import List, Optional


class SearchError(Exception):
    """Raised when a search operation fails."""


@dataclass
class SearchResult:
    """A single search match."""

    environment: str
    key: str
    version: int
    created_at: str
    updated_at: str

    def to_dict(self) -> dict:
        return {
            "environment": self.environment,
            "key": self.key,
            "version": self.version,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


def search_secrets(
    vault,
    pattern: str,
    *,
    environment: Optional[str] = None,
    use_regex: bool = False,
) -> List[SearchResult]:
    """Search for secrets whose keys match *pattern*.

    Args:
        vault: A :class:`~envault.vault.Vault` instance.
        pattern: A glob pattern (default) or regex string.
        environment: If given, restrict search to this environment.
        use_regex: Treat *pattern* as a regular expression.

    Returns:
        A list of :class:`SearchResult` objects sorted by environment then key.

    Raises:
        SearchError: If *pattern* is an invalid regex when *use_regex* is True.
    """
    if use_regex:
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            raise SearchError(f"Invalid regex pattern '{pattern}': {exc}") from exc
        match = compiled.search
    else:
        match = lambda key: fnmatch.fnmatch(key, pattern)  # noqa: E731

    environments = (
        [environment] if environment else vault.list_environments()
    )

    results: List[SearchResult] = []
    for env in environments:
        for key in vault.list_secrets(env):
            if match(key):
                entry = vault.get(env, key)
                if entry is None:
                    continue
                d = entry.to_dict()
                results.append(
                    SearchResult(
                        environment=env,
                        key=key,
                        version=d.get("version", 1),
                        created_at=d.get("created_at", ""),
                        updated_at=d.get("updated_at", ""),
                    )
                )

    results.sort(key=lambda r: (r.environment, r.key))
    return results
