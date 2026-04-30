"""CLI commands for secret feature flags."""
from __future__ import annotations

import json

import click

from envault.flag import FLAG_KEYS, FlagError, list_flags, set_flag, unset_flag


@click.group("flag", help="Manage boolean flags on secrets.")
def flag_group() -> None:  # pragma: no cover
    pass


@flag_group.command("set")
@click.argument("environment")
@click.argument("secret")
@click.argument("flag", type=click.Choice(list(FLAG_KEYS)))
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
def set_cmd(environment: str, secret: str, flag: str, vault_file: str, passphrase: str) -> None:
    """Add FLAG to SECRET in ENVIRONMENT."""
    from envault.vault import Vault

    vault = Vault(vault_file, passphrase)
    vault.load()
    try:
        result = set_flag(vault, environment, secret, flag)
    except FlagError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)
    click.echo(json.dumps(result.to_dict()))


@flag_group.command("unset")
@click.argument("environment")
@click.argument("secret")
@click.argument("flag")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
def unset_cmd(environment: str, secret: str, flag: str, vault_file: str, passphrase: str) -> None:
    """Remove FLAG from SECRET in ENVIRONMENT."""
    from envault.vault import Vault

    vault = Vault(vault_file, passphrase)
    vault.load()
    try:
        result = unset_flag(vault, environment, secret, flag)
    except FlagError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)
    click.echo(json.dumps(result.to_dict()))


@flag_group.command("list")
@click.argument("environment")
@click.argument("secret")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
def list_cmd(environment: str, secret: str, vault_file: str, passphrase: str) -> None:
    """List flags for SECRET in ENVIRONMENT."""
    from envault.vault import Vault

    vault = Vault(vault_file, passphrase)
    vault.load()
    try:
        result = list_flags(vault, environment, secret)
    except FlagError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)
    click.echo(json.dumps(result.to_dict()))
