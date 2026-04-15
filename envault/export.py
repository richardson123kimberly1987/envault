"""Export secrets to various formats (dotenv, JSON, shell)."""
from __future__ import annotations

import json
import shlex
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from envault.vault import Vault


SUPPORTED_FORMATS = ("dotenv", "json", "shell")


class ExportError(Exception):
    """Raised when export fails."""


def export_dotenv(vault: "Vault", environment: str) -> str:
    """Export secrets as a .env file string."""
    lines: list[str] = [f"# envault export — environment: {environment}"]
    secrets = vault.list_secrets(environment)
    if not secrets:
        return "\n".join(lines) + "\n"
    for key in sorted(secrets):
        value = vault.get_secret(key, environment)
        if value is not None:
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'{key}="{escaped}"')
    return "\n".join(lines) + "\n"


def export_json(vault: "Vault", environment: str) -> str:
    """Export secrets as a JSON string."""
    secrets = vault.list_secrets(environment)
    data: dict[str, str] = {}
    for key in sorted(secrets):
        value = vault.get_secret(key, environment)
        if value is not None:
            data[key] = value
    return json.dumps({"environment": environment, "secrets": data}, indent=2) + "\n"


def export_shell(vault: "Vault", environment: str) -> str:
    """Export secrets as shell export statements."""
    lines: list[str] = [f"# envault export — environment: {environment}"]
    secrets = vault.list_secrets(environment)
    for key in sorted(secrets):
        value = vault.get_secret(key, environment)
        if value is not None:
            lines.append(f"export {key}={shlex.quote(value)}")
    return "\n".join(lines) + "\n"


def export_secrets(vault: "Vault", environment: str, fmt: str) -> str:
    """Dispatch export to the requested format."""
    if fmt not in SUPPORTED_FORMATS:
        raise ExportError(
            f"Unsupported format '{fmt}'. Choose from: {', '.join(SUPPORTED_FORMATS)}"
        )
    if fmt == "dotenv":
        return export_dotenv(vault, environment)
    if fmt == "json":
        return export_json(vault, environment)
    return export_shell(vault, environment)
