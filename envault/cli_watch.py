"""CLI commands for the watch feature."""
from __future__ import annotations

import json
import sys

import click

from envault.cli import _get_vault
from envault.watch import WatchError, watch_environment


@click.group("watch")
def watch_group():
    """Watch an environment for secret changes."""


@watch_group.command("start")
@click.argument("environment")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
@click.option("--interval", default=5.0, show_default=True, help="Poll interval in seconds.")
@click.option("--format", "fmt", default="text", type=click.Choice(["text", "json"]), show_default=True)
def start_cmd(environment, vault_file, passphrase, interval, fmt):
    """Start watching ENVIRONMENT for secret changes (Ctrl-C to stop)."""
    try:
        vault = _get_vault(vault_file, passphrase)
    except Exception as exc:  # noqa: BLE001
        click.echo(f"Error loading vault: {exc}", err=True)
        sys.exit(1)

    click.echo(f"Watching '{environment}' every {interval}s — press Ctrl-C to stop.")

    def _on_event(event):
        if fmt == "json":
            click.echo(json.dumps(event.to_dict()))
        else:
            click.echo(
                f"[{event.event_type.upper()}] {event.environment}/{event.key} "
                f"{event.old_value!r} -> {event.new_value!r}"
            )

    try:
        watch_environment(vault, environment, _on_event, interval=interval)
    except WatchError as exc:
        click.echo(f"Watch error: {exc}", err=True)
        sys.exit(1)
    except KeyboardInterrupt:
        click.echo("\nWatch stopped.")
