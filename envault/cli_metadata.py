"""CLI commands for managing secret metadata."""
from __future__ import annotations

import json
import sys

import click

from envault.metadata import MetadataError, get_metadata, remove_metadata, set_metadata


@click.group(name="metadata", help="Manage metadata key/value pairs on secrets.")
def metadata_group() -> None:
    pass


@metadata_group.command(name="set", help="Set a metadata key on a secret.")
@click.argument("environment")
@click.argument("secret")
@click.argument("key")
@click.argument("value")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--json", "as_json", is_flag=True, default=False)
def set_cmd(environment: str, secret: str, key: str, value: str, vault_file: str, as_json: bool) -> None:
    from envault.cli import _get_vault
    vault = _get_vault(vault_file)
    try:
        result = set_metadata(vault, environment, secret, key, value)
    except MetadataError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
    if as_json:
        click.echo(json.dumps(result.to_dict()))
    else:
        click.echo(f"Set metadata '{key}' on {environment}/{secret}.")


@metadata_group.command(name="remove", help="Remove a metadata key from a secret.")
@click.argument("environment")
@click.argument("secret")
@click.argument("key")
@click.option("--vault-file", default="vault.json", show_default=True)
def remove_cmd(environment: str, secret: str, key: str, vault_file: str) -> None:
    from envault.cli import _get_vault
    vault = _get_vault(vault_file)
    try:
        remove_metadata(vault, environment, secret, key)
    except MetadataError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
    click.echo(f"Removed metadata '{key}' from {environment}/{secret}.")


@metadata_group.command(name="list", help="List all metadata for a secret.")
@click.argument("environment")
@click.argument("secret")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--json", "as_json", is_flag=True, default=False)
def list_cmd(environment: str, secret: str, vault_file: str, as_json: bool) -> None:
    from envault.cli import _get_vault
    vault = _get_vault(vault_file)
    try:
        result = get_metadata(vault, environment, secret)
    except MetadataError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
    if as_json:
        click.echo(json.dumps(result.to_dict()))
    else:
        if not result.metadata:
            click.echo("No metadata set.")
        else:
            for k, v in result.metadata.items():
                click.echo(f"  {k}: {v}")
