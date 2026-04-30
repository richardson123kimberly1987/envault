"""Register the flag command group with the main CLI."""
from __future__ import annotations


def register(cli) -> None:
    """Attach the flag sub-command group to *cli*."""
    from envault.cli_flag import flag_group

    cli.add_command(flag_group)
