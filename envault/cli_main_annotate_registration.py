"""Registration helper: attach the annotate group to the main CLI.

Import this module in envault/cli_main.py to activate annotation commands::

    from envault.cli_main_annotate_registration import register
    register(cli)
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import click

from envault.cli_annotate import annotate_group


def register(cli: "click.Group") -> None:
    """Attach the *annotate* sub-group to *cli* if not already registered."""
    existing_names = {cmd for cmd in cli.commands}
    if "annotate" not in existing_names:
        cli.add_command(annotate_group, name="annotate")
