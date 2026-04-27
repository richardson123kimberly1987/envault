"""Annotation support for secret entries."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

ANNOTATION_MAX_LENGTH = 1024


class AnnotateError(Exception):
    """Raised when an annotation operation fails."""


@dataclass
class AnnotateResult:
    secret: str
    environment: str
    annotation: str
    previous: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "secret": self.secret,
            "environment": self.environment,
            "annotation": self.annotation,
            "previous": self.previous,
        }


def _get_entry_or_raise(vault: Any, environment: str, secret: str) -> Any:
    entry = vault.get_secret(environment, secret)
    if entry is None:
        raise AnnotateError(
            f"Secret '{secret}' not found in environment '{environment}'."
        )
    return entry


def set_annotation(vault: Any, environment: str, secret: str, annotation: str) -> AnnotateResult:
    """Set or replace the annotation on a secret entry."""
    if len(annotation) > ANNOTATION_MAX_LENGTH:
        raise AnnotateError(
            f"Annotation exceeds maximum length of {ANNOTATION_MAX_LENGTH} characters."
        )
    entry = _get_entry_or_raise(vault, environment, secret)
    data = entry.to_dict()
    previous = data.get("annotation") or None
    data["annotation"] = annotation
    entry.update_value(data.get("value", ""), extra={"annotation": annotation})
    vault.save()
    return AnnotateResult(
        secret=secret,
        environment=environment,
        annotation=annotation,
        previous=previous,
    )


def remove_annotation(vault: Any, environment: str, secret: str) -> AnnotateResult:
    """Remove the annotation from a secret entry."""
    entry = _get_entry_or_raise(vault, environment, secret)
    data = entry.to_dict()
    previous = data.get("annotation") or None
    entry.update_value(data.get("value", ""), extra={"annotation": None})
    vault.save()
    return AnnotateResult(
        secret=secret,
        environment=environment,
        annotation="",
        previous=previous,
    )


def get_annotation(vault: Any, environment: str, secret: str) -> str | None:
    """Return the annotation for a secret, or None if unset."""
    entry = _get_entry_or_raise(vault, environment, secret)
    return entry.to_dict().get("annotation") or None
