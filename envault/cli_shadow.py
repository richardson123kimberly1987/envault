"""CLI commands for shadow copy management."""
from __future__ import annotations

import json

import click

from envault.shadow import ShadowError, capture_shadow, clear_shadow, get_shadow


@click.group("shadow", help="Manage shadow (previous) copies of secrets.")
def shadow_group() -> None:
    pass


@shadow_group.command("capture")
@click.argument("environment")
@click.argument("secret")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
@click.option("--json", "as_json", is_flag=True, default=False)
def capture_cmd(
    environment: str,
    secret: str,
    vault_file: str,
    passphrase: str,
    as_json: bool,
) -> None:
    """Capture the current value as a shadow copy."""
    from envault.vault import Vault

    vault = Vault(vault_file, passphrase)
    vault.load()
    try:
        result = capture_shadow(vault, environment, secret)
    except ShadowError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)
    if as_json:
        click.echo(json.dumps(result.to_dict(), indent=2))
    else:
        status = "updated" if result.had_shadow else "created"
        click.echo(f"Shadow {status} for '{secret}' in '{environment}'.")


@shadow_group.command("get")
@click.argument("environment")
@click.argument("secret")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
@click.option("--json", "as_json", is_flag=True, default=False)
def get_cmd(
    environment: str,
    secret: str,
    vault_file: str,
    passphrase: str,
    as_json: bool,
) -> None:
    """Show the shadow (previous) value of a secret."""
    from envault.vault import Vault

    vault = Vault(vault_file, passphrase)
    vault.load()
    try:
        result = get_shadow(vault, environment, secret)
    except ShadowError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)
    if as_json:
        click.echo(json.dumps(result.to_dict(), indent=2))
    elif result.had_shadow:
        click.echo(result.previous_value)
    else:
        click.echo(f"No shadow copy exists for '{secret}' in '{environment}'.")


@shadow_group.command("clear")
@click.argument("environment")
@click.argument("secret")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
def clear_cmd(
    environment: str,
    secret: str,
    vault_file: str,
    passphrase: str,
) -> None:
    """Remove the shadow copy from a secret."""
    from envault.vault import Vault

    vault = Vault(vault_file, passphrase)
    vault.load()
    try:
        result = clear_shadow(vault, environment, secret)
    except ShadowError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)
    if result.had_shadow:
        click.echo(f"Shadow cleared for '{secret}' in '{environment}'.")
    else:
        click.echo(f"No shadow to clear for '{secret}' in '{environment}'.")
