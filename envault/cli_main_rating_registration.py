"""Registration shim: attaches the rating CLI group to the main CLI.

Import and call ``register(cli)`` from cli_main.py to enable the
``envault rating`` sub-command group.
"""
from __future__ import annotations

import click

from envault.cli_rating import rating_group


def register(cli: click.Group) -> None:  # pragma: no cover
    """Attach rating_group to the top-level *cli* group."""
    cli.add_command(rating_group, name="rating")
