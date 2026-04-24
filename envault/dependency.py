"""Secret dependency tracking — record and resolve inter-secret dependencies."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

DEPENDENCY_KEY = "__dependencies__"


class DependencyError(Exception):
    """Raised when a dependency operation fails."""


@dataclass
class DependencyResult:
    secret: str
    environment: str
    depends_on: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "secret": self.secret,
            "environment": self.environment,
            "depends_on": list(self.depends_on),
        }


def _load_deps(vault) -> Dict[str, Dict[str, List[str]]]:
    """Return {env: {secret: [dep, ...]}} from vault metadata."""
    raw = vault.get_secret(DEPENDENCY_KEY, "__meta__")
    if raw is None:
        return {}
    import json
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return {}


def _save_deps(vault, data: Dict[str, Dict[str, List[str]]]) -> None:
    import json
    vault.set_secret(DEPENDENCY_KEY, "__meta__", json.dumps(data))


def add_dependency(vault, secret: str, environment: str, depends_on: str) -> DependencyResult:
    """Record that *secret* in *environment* depends on *depends_on*."""
    if vault.get_secret(secret, environment) is None:
        raise DependencyError(f"Secret '{secret}' not found in environment '{environment}'")
    if vault.get_secret(depends_on, environment) is None:
        raise DependencyError(f"Dependency '{depends_on}' not found in environment '{environment}'")
    data = _load_deps(vault)
    env_data = data.setdefault(environment, {})
    deps = env_data.setdefault(secret, [])
    if depends_on not in deps:
        deps.append(depends_on)
    _save_deps(vault, data)
    return DependencyResult(secret=secret, environment=environment, depends_on=list(deps))


def remove_dependency(vault, secret: str, environment: str, depends_on: str) -> DependencyResult:
    """Remove a recorded dependency."""
    data = _load_deps(vault)
    deps = data.get(environment, {}).get(secret, [])
    if depends_on not in deps:
        raise DependencyError(f"Dependency '{depends_on}' not found for '{secret}'")
    deps.remove(depends_on)
    data.setdefault(environment, {})[secret] = deps
    _save_deps(vault, data)
    return DependencyResult(secret=secret, environment=environment, depends_on=list(deps))


def list_dependencies(vault, secret: str, environment: str) -> DependencyResult:
    """Return all dependencies for *secret* in *environment*."""
    data = _load_deps(vault)
    deps = data.get(environment, {}).get(secret, [])
    return DependencyResult(secret=secret, environment=environment, depends_on=list(deps))


def resolve_order(vault, environment: str) -> List[str]:
    """Return secrets in *environment* sorted by dependency order (topological)."""
    data = _load_deps(vault)
    graph = data.get(environment, {})
    all_secrets = list(vault.list_secrets(environment))
    visited: List[str] = []
    visiting: set = set()

    def visit(node: str) -> None:
        if node in visiting:
            raise DependencyError(f"Circular dependency detected at '{node}'")
        if node in visited:
            return
        visiting.add(node)
        for dep in graph.get(node, []):
            visit(dep)
        visiting.discard(node)
        visited.append(node)

    for s in all_secrets:
        visit(s)
    return visited
