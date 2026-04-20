"""CLI commands for locking and unlocking secrets."""
import click

from envault.cli import _get_vault
from envault.lock import LockError, lock_secret, unlock_secret, list_locked


@click.group("lock")
def lock_group():
    """Lock or unlock secrets to prevent accidental modification."""


@lock_group.command("set")
@click.argument("environment")
@click.argument("key")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
def set_cmd(environment: str, key: str, vault_file: str, passphrase: str):
    """Lock a secret to prevent modification."""
    vault = _get_vault(vault_file, passphrase)
    try:
        result = lock_secret(vault, environment, key)
        click.echo(result.message)
    except LockError as exc:
        raise click.ClickException(str(exc))


@lock_group.command("unset")
@click.argument("environment")
@click.argument("key")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
def unset_cmd(environment: str, key: str, vault_file: str, passphrase: str):
    """Unlock a secret to allow modification."""
    vault = _get_vault(vault_file, passphrase)
    try:
        result = unlock_secret(vault, environment, key)
        click.echo(result.message)
    except LockError as exc:
        raise click.ClickException(str(exc))


@lock_group.command("list")
@click.argument("environment")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
def list_cmd(environment: str, vault_file: str, passphrase: str):
    """List all locked secrets in an environment."""
    vault = _get_vault(vault_file, passphrase)
    try:
        keys = list_locked(vault, environment)
    except LockError as exc:
        raise click.ClickException(str(exc))

    if not keys:
        click.echo(f"No locked secrets in '{environment}'.")
    else:
        click.echo(f"Locked secrets in '{environment}':")
        for k in keys:
            click.echo(f"  {k}")
