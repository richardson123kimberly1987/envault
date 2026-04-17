"""Main CLI entry-point that registers all command groups."""
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
from envault.cli_merge import merge_group
from envault.cli_promote import promote_group
from envault.cli_pin import pin_group
from envault.cli_validate import validate_group
from envault.cli_notify import notify_group

cli.add_command(snapshot_group)
cli.add_command(tag_group)
cli.add_command(access_group)
cli.add_command(expiry_group)
cli.add_command(template_group)
cli.add_command(lint_group)
cli.add_command(history_group)
cli.add_command(compare_group)
cli.add_command(rename_group)
cli.add_command(merge_group)
cli.add_command(promote_group)
cli.add_command(pin_group)
cli.add_command(validate_group)
cli.add_command(notify_group)

if __name__ == "__main__":
    cli()
