"""CLI commands for the checkpoint feature."""
from __future__ import annotations

import json

import click

from envault.checkpoint import (
    CheckpointError,
    CHECKPOINT_FILE,
    list_checkpoints,
    restore_checkpoint,
    save_checkpoint,
)
from envault.cli import _get_vault


@click.group("checkpoint")
def checkpoint_group() -> None:
    """Save and restore named vault checkpoints."""


@checkpoint_group.command("save")
@click.argument("environment")
@click.argument("name")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
@click.option("--checkpoint-file", default=CHECKPOINT_FILE, show_default=True)
def save_cmd(
    environment: str,
    name: str,
    vault_file: str,
    passphrase: str,
    checkpoint_file: str,
) -> None:
    """Save the current state of ENVIRONMENT as checkpoint NAME."""
    vault = _get_vault(vault_file, passphrase)
    try:
        cp = save_checkpoint(vault, environment, name, checkpoint_file)
        click.echo(f"Checkpoint '{cp.name}' saved for environment '{cp.environment}'.")
    except CheckpointError as exc:
        raise click.ClickException(str(exc)) from exc


@checkpoint_group.command("restore")
@click.argument("environment")
@click.argument("name")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
@click.option("--checkpoint-file", default=CHECKPOINT_FILE, show_default=True)
def restore_cmd(
    environment: str,
    name: str,
    vault_file: str,
    passphrase: str,
    checkpoint_file: str,
) -> None:
    """Restore ENVIRONMENT from checkpoint NAME."""
    vault = _get_vault(vault_file, passphrase)
    try:
        cp = restore_checkpoint(vault, environment, name, checkpoint_file)
        vault.save()
        click.echo(f"Environment '{cp.environment}' restored from checkpoint '{cp.name}'.")
    except CheckpointError as exc:
        raise click.ClickException(str(exc)) from exc


@checkpoint_group.command("list")
@click.argument("environment")
@click.option("--checkpoint-file", default=CHECKPOINT_FILE, show_default=True)
@click.option("--json", "as_json", is_flag=True, default=False)
def list_cmd(environment: str, checkpoint_file: str, as_json: bool) -> None:
    """List all checkpoints for ENVIRONMENT."""
    checkpoints = list_checkpoints(environment, checkpoint_file)
    if as_json:
        click.echo(json.dumps([c.to_dict() for c in checkpoints], indent=2))
    elif checkpoints:
        for cp in checkpoints:
            click.echo(f"{cp.name}  (created {cp.created_at:.0f})")
    else:
        click.echo(f"No checkpoints found for environment '{environment}'.")
