"""Import secrets into a vault from external formats (dotenv, JSON)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Dict, Optional

if TYPE_CHECKING:
    from envault.vault import Vault

__all__ = ["ImportError", "import_dotenv", "import_json", "import_secrets"]


class ImportError(Exception):  # noqa: A001
    """Raised when an import operation fails."""


_DOTENV_LINE = re.compile(
    r"^\s*(?P<key>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<value>.*)\s*$"
)


def import_dotenv(
    source: str,
    vault: "Vault",
    environment: str,
    overwrite: bool = False,
) -> Dict[str, str]:
    """Parse *source* as a .env file and write secrets into *vault*.

    Returns a mapping of key -> value for every secret that was imported.
    Raises :class:`ImportError` on parse errors.
    """
    imported: Dict[str, str] = {}
    for lineno, raw in enumerate(source.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _DOTENV_LINE.match(line)
        if not m:
            raise ImportError(f"Invalid .env syntax on line {lineno}: {raw!r}")
        key, value = m.group("key"), m.group("value")
        # Strip optional surrounding quotes
        for quote in ('"', "'"):
            if value.startswith(quote) and value.endswith(quote) and len(value) >= 2:
                value = value[1:-1]
                break
        if overwrite or vault.get_secret(environment, key) is None:
            vault.set_secret(environment, key, value)
            imported[key] = value
    return imported


def import_json(
    source: str,
    vault: "Vault",
    environment: str,
    overwrite: bool = False,
) -> Dict[str, str]:
    """Parse *source* as a JSON object ``{key: value, ...}`` and write secrets.

    Returns a mapping of key -> value for every secret that was imported.
    Raises :class:`ImportError` on invalid JSON or unexpected structure.
    """
    try:
        data = json.loads(source)
    except json.JSONDecodeError as exc:
        raise ImportError(f"Invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ImportError("JSON root must be an object mapping keys to string values.")
    imported: Dict[str, str] = {}
    for key, value in data.items():
        if not isinstance(key, str):
            raise ImportError(f"JSON key must be a string, got {type(key).__name__!r}.")
        if not isinstance(value, str):
            value = str(value)
        if overwrite or vault.get_secret(environment, key) is None:
            vault.set_secret(environment, key, value)
            imported[key] = value
    return imported


def import_secrets(
    source: str,
    fmt: str,
    vault: "Vault",
    environment: str,
    overwrite: bool = False,
) -> Dict[str, str]:
    """Dispatch to the correct importer based on *fmt* (``'dotenv'`` or ``'json'``)."""
    fmt = fmt.lower()
    if fmt == "dotenv":
        return import_dotenv(source, vault, environment, overwrite=overwrite)
    if fmt == "json":
        return import_json(source, vault, environment, overwrite=overwrite)
    raise ImportError(f"Unsupported import format: {fmt!r}. Choose 'dotenv' or 'json'.")
