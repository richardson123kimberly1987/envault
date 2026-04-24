"""CLI commands for secret grouping."""

from __future__ import annotations

import click

from envault.cli import _get_vault
from envault.group import GroupError, add_to_group, remove_from_group, list_group


@click.group("group", help="Organise secrets into named groups.")
def group_group() -> None:  # noqa: D401
    pass


@group_group.command("add", help="Add a secret to a group.")
@click.argument("group_name")
@click.argument("secret")
@click.option("--env", "environment", default="default", show_default=True,
              help="Target environment.")
@click.option("--vault", "vault_path", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
def add_cmd(group_name: str, secret: str, environment: str,
            vault_path: str, passphrase: str) -> None:
    vault = _get_vault(vault_path, passphrase)
    try:
        result = add_to_group(vault, group_name, secret, environment)
        click.echo(f"Added '{result.secret}' to group '{result.group}' "
                   f"in '{result.environment}'. Members: {result.members}")
    except GroupError as exc:
        raise click.ClickException(str(exc)) from exc


@group_group.command("remove", help="Remove a secret from a group.")
@click.argument("group_name")
@click.argument("secret")
@click.option("--env", "environment", default="default", show_default=True)
@click.option("--vault", "vault_path", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
def remove_cmd(group_name: str, secret: str, environment: str,
               vault_path: str, passphrase: str) -> None:
    vault = _get_vault(vault_path, passphrase)
    try:
        result = remove_from_group(vault, group_name, secret, environment)
        click.echo(f"Removed '{result.secret}' from group '{result.group}'. "
                   f"Remaining members: {result.members}")
    except GroupError as exc:
        raise click.ClickException(str(exc)) from exc


@group_group.command("list", help="List secrets in a group.")
@click.argument("group_name")
@click.option("--env", "environment", default="default", show_default=True)
@click.option("--vault", "vault_path", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
def list_cmd(group_name: str, environment: str,
             vault_path: str, passphrase: str) -> None:
    vault = _get_vault(vault_path, passphrase)
    result = list_group(vault, group_name, environment)
    if result.members:
        click.echo(f"Group '{group_name}' in '{environment}':")
        for member in result.members:
            click.echo(f"  - {member}")
    else:
        click.echo(f"Group '{group_name}' in '{environment}' is empty or does not exist.")
