"""CLI commands for snapshot/restore operations."""
from __future__ import annotations

import click

from envault.snapshot import (
    SnapshotError,
    load_snapshot,
    restore_snapshot,
    save_snapshot,
    take_snapshot,
)


@click.group("snapshot")
def snapshot_group() -> None:
    """Commands for snapshotting and restoring vault environments."""


@snapshot_group.command("take")
@click.argument("environment")
@click.argument("output")
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
@click.pass_context
def take_cmd(ctx: click.Context, environment: str, output: str, passphrase: str) -> None:
    """Take a snapshot of ENVIRONMENT and write it to OUTPUT (JSON file)."""
    from envault.cli import _get_vault  # local import to avoid circular deps

    vault = _get_vault(ctx, passphrase)
    try:
        snap = take_snapshot(vault, environment)
        save_snapshot(snap, output)
        click.echo(f"Snapshot of '{environment}' saved to {output} ({len(snap.data)} secret(s)).")
    except SnapshotError as exc:
        raise click.ClickException(str(exc)) from exc


@snapshot_group.command("restore")
@click.argument("input_file")
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
@click.option("--yes", is_flag=True, default=False, help="Skip confirmation prompt.")
@click.pass_context
def restore_cmd(ctx: click.Context, input_file: str, passphrase: str, yes: bool) -> None:
    """Restore secrets from INPUT_FILE (JSON snapshot) into the vault."""
    from envault.cli import _get_vault

    try:
        snap = load_snapshot(input_file)
    except SnapshotError as exc:
        raise click.ClickException(str(exc)) from exc

    if not yes:
        click.confirm(
            f"Restore {len(snap.data)} secret(s) into environment '{snap.environment}'?",
            abort=True,
        )

    vault = _get_vault(ctx, passphrase)
    try:
        count = restore_snapshot(vault, snap, passphrase)
        click.echo(f"Restored {count} secret(s) into '{snap.environment}'.")
    except SnapshotError as exc:
        raise click.ClickException(str(exc)) from exc


@snapshot_group.command("list")
@click.argument("snapshot_file")
def list_cmd(snapshot_file: str) -> None:
    """List secrets contained in SNAPSHOT_FILE."""
    try:
        snap = load_snapshot(snapshot_file)
    except SnapshotError as exc:
        raise click.ClickException(str(exc)) from exc

    click.echo(f"Environment : {snap.environment}")
    click.echo(f"Created at  : {snap.created_at}")
    click.echo(f"Secrets ({len(snap.data)}):")
    for key in sorted(snap.data.keys()):
        click.echo(f"  {key}")
