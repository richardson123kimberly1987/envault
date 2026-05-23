"""CLI commands for retiring and unretiring secrets."""
from __future__ import annotations

import click

from envault.retire import RetireError, retire_secret, unretire_secret, list_retired


@click.group("retire", help="Retire or restore secrets.")
def retire_group() -> None:
    pass


@retire_group.command("secret")
@click.argument("environment")
@click.argument("secret")
@click.option("--vault-file", default="vault.json", show_default=True, help="Path to vault file.")
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
def retire_cmd(environment: str, secret: str, vault_file: str, passphrase: str) -> None:
    """Retire a secret (soft-delete)."""
    from envault.vault import Vault

    vault = Vault(vault_file, passphrase)
    vault.load()
    try:
        result = retire_secret(vault, environment, secret)
        click.echo(f"Retired '{result.secret}' in '{result.environment}' at {result.retired_at}.")
    except RetireError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)


@retire_group.command("restore")
@click.argument("environment")
@click.argument("secret")
@click.option("--vault-file", default="vault.json", show_default=True, help="Path to vault file.")
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
def restore_cmd(environment: str, secret: str, vault_file: str, passphrase: str) -> None:
    """Restore a retired secret to active state."""
    from envault.vault import Vault

    vault = Vault(vault_file, passphrase)
    vault.load()
    try:
        result = unretire_secret(vault, environment, secret)
        click.echo(f"Restored '{result.secret}' in '{result.environment}' to active.")
    except RetireError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)


@retire_group.command("list")
@click.argument("environment")
@click.option("--vault-file", default="vault.json", show_default=True, help="Path to vault file.")
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
@click.option("--json", "as_json", is_flag=True, default=False, help="Output as JSON.")
def list_cmd(environment: str, vault_file: str, passphrase: str, as_json: bool) -> None:
    """List all retired secrets in an environment."""
    import json as _json
    from envault.vault import Vault

    vault = Vault(vault_file, passphrase)
    vault.load()
    results = list_retired(vault, environment)
    if as_json:
        click.echo(_json.dumps([r.to_dict() for r in results], indent=2))
    elif results:
        for r in results:
            click.echo(f"{r.secret}  (retired at {r.retired_at})")
    else:
        click.echo(f"No retired secrets in environment '{environment}'.")
