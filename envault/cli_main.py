"""Entry point that registers all CLI sub-groups."""
from __future__ import annotations

import click

from envault.cli import cli, set_secret, get_secret
from envault.cli_snapshot import snapshot_group
from envault.cli_tags import tag_group
from envault.cli_access import access_group
from envault.cli_expiry import expiry_group
from envault.cli_template import template_group
from envault.cli_lint import lint_group
from envault.cli_history import history_group
from envault.cli_compare import compare_group
from envault.cli_rename import rename_group

cli.add_command(snapshot_group)
cli.add_command(tag_group)
cli.add_command(access_group)
cli.add_command(expiry_group)
cli.add_command(template_group)
cli.add_command(lint_group)
cli.add_command(history_group)
cli.add_command(compare_group)
cli.add_command(rename_group)

if __name__ == "__main__":
    cli()
