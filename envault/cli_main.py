"""Main CLI entry-point that registers all command groups including expiry."""

from __future__ import annotations

import click

from envault.cli import cli, set_secret, get_secret
from envault.cli_snapshot import snapshot_group
from envault.cli_tags import tag_group
from envault.cli_access import access_group
from envault.cli_expiry import expiry_group


cli.add_command(snapshot_group, name="snapshot")
cli.add_command(tag_group, name="tag")
cli.add_command(access_group, name="access")
cli.add_command(expiry_group, name="expiry")


if __name__ == "__main__":
    cli()
