"""Command-line interface for envault."""

import os
import sys
from pathlib import Path

import click

from envault.vault import Vault, VaultError

DEFAULT_VAULT_FILE = ".envault"


def _get_vault(vault_path: str, passphrase: str) -> Vault:
    vault = Vault(path=Path(vault_path), passphrase=passphrase)
    vault.load()
    return vault


@click.group()
@click.option("--vault", default=DEFAULT_VAULT_FILE, show_default=True, help="Path to vault file.")
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True, help="Vault passphrase.")
@click.pass_context
def cli(ctx: click.Context, vault: str, passphrase: str) -> None:
    """envault — securely manage environment variable secrets."""
    ctx.ensure_object(dict)
    ctx.obj["vault_path"] = vault
    ctx.obj["passphrase"] = passphrase


@cli.command("set")
@click.argument("env")
@click.argument("key")
@click.argument("value")
@click.pass_context
def set_secret(ctx: click.Context, env: str, key: str, value: str) -> None:
    """Set a secret KEY=VALUE for ENV."""
    try:
        v = _get_vault(ctx.obj["vault_path"], ctx.obj["passphrase"])
        v.set_secret(env, key, value)
        v.save()
        click.echo(f"✓ Set '{key}' in [{env}]")
    except VaultError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


@cli.command("get")
@click.argument("env")
@click.argument("key")
@click.pass_context
def get_secret(ctx: click.Context, env: str, key: str) -> None:
    """Get the value of KEY in ENV."""
    try:
        v = _get_vault(ctx.obj["vault_path"], ctx.obj["passphrase"])
        value = v.get_secret(env, key)
        if value is None:
            click.echo(f"Key '{key}' not found in [{env}]", err=True)
            sys.exit(1)
        click.echo(value)
    except VaultError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


@cli.command("delete")
@click.argument("env")
@click.argument("key")
@click.pass_context
def delete_secret(ctx: click.Context, env: str, key: str) -> None:
    """Delete KEY from ENV."""
    try:
        v = _get_vault(ctx.obj["vault_path"], ctx.obj["passphrase"])
        removed = v.delete_secret(env, key)
        if removed:
            v.save()
            click.echo(f"✓ Deleted '{key}' from [{env}]")
        else:
            click.echo(f"Key '{key}' not found in [{env}]", err=True)
            sys.exit(1)
    except VaultError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


@cli.command("list")
@click.argument("env")
@click.pass_context
def list_keys(ctx: click.Context, env: str) -> None:
    """List all keys stored in ENV."""
    try:
        v = _get_vault(ctx.obj["vault_path"], ctx.obj["passphrase"])
        keys = v.list_keys(env)
        if not keys:
            click.echo(f"No secrets found in [{env}]")
        for k in keys:
            click.echo(k)
    except VaultError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
