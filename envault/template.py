"""Template rendering for secrets — interpolate vault secrets into string templates."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

# Matches {{ SECRET_NAME }} or {{ SECRET_NAME:default }}
_PLACEHOLDER_RE = re.compile(r"\{\{\s*([A-Za-z0-9_]+)(?::([^}]*))?\s*\}\}")


class TemplateError(Exception):
    """Raised when template rendering fails."""


@dataclass
class RenderResult:
    rendered: str
    resolved: list[str]
    missing: list[str]

    def to_dict(self) -> dict:
        return {
            "rendered": self.rendered,
            "resolved": self.resolved,
            "missing": self.missing,
        }


def list_placeholders(template: str) -> list[str]:
    """Return a deduplicated list of placeholder key names found in *template*.

    Useful for pre-flight checks — callers can verify that all required secrets
    exist before attempting a full render.

    Example
    -------
    >>> list_placeholders("Hello {{ NAME }}, your token is {{ TOKEN:none }}")
    ['NAME', 'TOKEN']
    """
    seen: dict[str, None] = {}  # ordered set via insertion-ordered dict
    for match in _PLACEHOLDER_RE.finditer(template):
        seen[match.group(1)] = None
    return list(seen)


def render_template(
    template: str,
    vault,
    environment: str,
    strict: bool = False,
) -> RenderResult:
    """Render *template*, replacing ``{{ KEY }}`` placeholders with vault secrets.

    Parameters
    ----------
    template:    The raw template string.
    vault:       A :class:`~envault.vault.Vault` instance.
    environment: The environment to look secrets up from.
    strict:      When *True*, raise :class:`TemplateError` if any placeholder
                 cannot be resolved (no default provided).
    """
    resolved: list[str] = []
    missing: list[str] = []

    def _replace(match: re.Match) -> str:
        key: str = match.group(1)
        default: Optional[str] = match.group(2)  # None when no default given

        entry = vault.get_secret(environment, key)
        if entry is not None:
            resolved.append(key)
            return entry.value if hasattr(entry, "value") else str(entry)

        if default is not None:
            missing.append(key)
            return default

        missing.append(key)
        if strict:
            raise TemplateError(
                f"Secret '{key}' not found in environment '{environment}' "
                "and no default was provided."
            )
        return match.group(0)  # leave placeholder as-is

    rendered = _PLACEHOLDER_RE.sub(_replace, template)
    return RenderResult(rendered=rendered, resolved=resolved, missing=missing)
