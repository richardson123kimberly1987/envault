"""CLI commands for pinning secrets to specific versions."""
import click
from envault.cli import _get_vault
from envault.pin import pin_secret, unpin_secret, list_pinned, PinError


@click.group("pin")
def pin_group():
    """Pin secrets to prevent accidental overwrites."""


@pin_group.command("set")
@click.argument("environment")
@click.argument("key")
@click.argument("version")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
def set_cmd(environment, key, version, vault_file, passphrase):
    """Pin KEY in ENVIRONMENT to VERSION."""
    vault = _get_vault(vault_file, passphrase)
    try:
        result = pin_secret(vault, environment, key, version)
        vault.save()
        click.echo(f"Pinned '{result.key}' to version '{result.version}' in '{result.environment}'.")
    except PinError as exc:
        raise click.ClickException(str(exc))


@pin_group.command("unset")
@click.argument("environment")
@click.argument("key")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
def unset_cmd(environment, key, vault_file, passphrase):
    """Remove the pin from KEY in ENVIRONMENT."""
    vault = _get_vault(vault_file, passphrase)
    try:
        result = unpin_secret(vault, environment, key)
        vault.save()
        click.echo(f"Unpinned '{result.key}' in '{result.environment}'.")
    except PinError as exc:
        raise click.ClickException(str(exc))


@pin_group.command("list")
@click.argument("environment")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
def list_cmd(environment, vault_file, passphrase):
    """List all pinned secrets in ENVIRONMENT."""
    vault = _get_vault(vault_file, passphrase)
    results = list_pinned(vault, environment)
    if not results:
        click.echo("No pinned secrets.")
        return
    for r in results:
        click.echo(f"{r.key}  =>  {r.version}")
