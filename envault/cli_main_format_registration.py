"""Register the format command group with the main CLI."""
from __future__ import annotations

from envault.cli_format import format_group


def register(cli) -> None:  # noqa: ANN001
    """Attach the format command group to *cli*."""
    cli.add_command(format_group, name="format")
