"""Main CLI entry-point that registers all command groups."""
from __future__ import annotations

import click

from envault.cli import cli
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
from envault.cli_lock import lock_group
from envault.cli_scope import scope_group
from envault.cli_watch import watch_group

# Register all sub-groups
cli.add_command(snapshot_group, "snapshot")
cli.add_command(tag_group, "tag")
cli.add_command(access_group, "access")
cli.add_command(expiry_group, "expiry")
cli.add_command(template_group, "template")
cli.add_command(lint_group, "lint")
cli.add_command(history_group, "history")
cli.add_command(compare_group, "compare")
cli.add_command(rename_group, "rename")
cli.add_command(merge_group, "merge")
cli.add_command(promote_group, "promote")
cli.add_command(pin_group, "pin")
cli.add_command(validate_group, "validate")
cli.add_command(notify_group, "notify")
cli.add_command(lock_group, "lock")
cli.add_command(scope_group, "scope")
cli.add_command(watch_group, "watch")


if __name__ == "__main__":
    cli()
