"""Pipeline: chain multiple secret transformations into a single operation."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


class PipelineError(Exception):
    """Raised when a pipeline step fails."""


@dataclass
class PipelineStep:
    name: str
    transform: Callable[[str], str]

    def apply(self, value: str) -> str:
        try:
            return self.transform(value)
        except Exception as exc:  # noqa: BLE001
            raise PipelineError(f"Step '{self.name}' failed: {exc}") from exc


@dataclass
class PipelineResult:
    key: str
    environment: str
    original: str
    final: str
    steps_applied: List[str] = field(default_factory=list)
    skipped: bool = False
    skip_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "environment": self.environment,
            "original": self.original,
            "final": self.final,
            "steps_applied": self.steps_applied,
            "skipped": self.skipped,
            "skip_reason": self.skip_reason,
        }


def run_pipeline(
    vault: Any,
    environment: str,
    key: str,
    steps: List[PipelineStep],
    *,
    dry_run: bool = False,
) -> PipelineResult:
    """Apply a sequence of transformation steps to a secret value."""
    entry = vault.get_secret(environment, key)
    if entry is None:
        raise PipelineError(f"Secret '{key}' not found in environment '{environment}'")

    raw = entry.to_dict().get("value", "")
    current = raw
    applied: List[str] = []

    for step in steps:
        current = step.apply(current)
        applied.append(step.name)

    result = PipelineResult(
        key=key,
        environment=environment,
        original=raw,
        final=current,
        steps_applied=applied,
    )

    if not dry_run and current != raw:
        vault.set_secret(environment, key, current)
        vault.save()

    return result


def run_pipeline_all(
    vault: Any,
    environment: str,
    steps: List[PipelineStep],
    *,
    dry_run: bool = False,
) -> List[PipelineResult]:
    """Apply a pipeline to every secret in an environment."""
    keys = vault.list_secrets(environment)
    return [run_pipeline(vault, environment, k, steps, dry_run=dry_run) for k in keys]
