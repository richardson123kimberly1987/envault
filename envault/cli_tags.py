"""CLI commands for tag management (envault tag ...)."""

from __future__ import annotations

import click

from envault.cli import _get_vault
from envault.tags import TagError, add_tag, list_by_tag, remove_tag


@click.group("tag")
def tag_group() -> None:
    """Manage tags on secrets."""


@tag_group.command("add")
@click.argument("environment")
@click.argument("key")
@click.argument("tag")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
def add_cmd(environment: str, key: str, tag: str, vault_file: str, passphrase: str) -> None:
    """Add TAG to a secret KEY in ENVIRONMENT."""
    vault = _get_vault(vault_file, passphrase)
    try:
        add_tag(vault, environment, key, tag)
        vault.save()
        click.echo(f"Tag '{tag}' added to '{key}' in '{environment}'.")
    except TagError as exc:
        raise click.ClickException(str(exc)) from exc


@tag_group.command("remove")
@click.argument("environment")
@click.argument("key")
@click.argument("tag")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
def remove_cmd(
    environment: str, key: str, tag: str, vault_file: str, passphrase: str
) -> None:
    """Remove TAG from a secret KEY in ENVIRONMENT."""
    vault = _get_vault(vault_file, passphrase)
    try:
        remove_tag(vault, environment, key, tag)
        vault.save()
        click.echo(f"Tag '{tag}' removed from '{key}' in '{environment}'.")
    except TagError as exc:
        raise click.ClickException(str(exc)) from exc


@tag_group.command("list")
@click.argument("tag")
@click.option("--environment", default=None, help="Filter to a specific environment.")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
def list_cmd(tag: str, environment: str | None, vault_file: str, passphrase: str) -> None:
    """List all secrets carrying TAG."""
    vault = _get_vault(vault_file, passphrase)
    results = list_by_tag(vault, tag, environment=environment)
    if not results:
        click.echo("No secrets found with that tag.")
        return
    for r in results:
        click.echo(f"{r.environment}  {r.key}  [{', '.join(r.tags)}]")
