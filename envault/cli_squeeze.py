"""CLI commands for the squeeze feature."""
from __future__ import annotations

import json

import click

from envault.squeeze import SqueezeError, squeeze_environment


@click.group("squeeze")
def squeeze_group() -> None:
    """Remove blank/whitespace-only secrets from an environment."""


@squeeze_group.command("run")
@click.argument("vault_file", type=click.Path(exists=True))
@click.argument("environment")
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
@click.option("--dry-run", is_flag=True, default=False, help="Preview without mutating.")
@click.option("--json", "as_json", is_flag=True, default=False)
def run_cmd(
    vault_file: str,
    environment: str,
    passphrase: str,
    dry_run: bool,
    as_json: bool,
) -> None:
    """Squeeze blank secrets from ENVIRONMENT in VAULT_FILE."""
    from envault.vault import Vault

    vault = Vault(vault_file, passphrase)
    vault.load()

    try:
        result = squeeze_environment(vault, environment, dry_run=dry_run)
    except SqueezeError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1) from exc

    if as_json:
        click.echo(json.dumps(result.to_dict(), indent=2))
        return

    label = "[dry-run] " if dry_run else ""
    if result.removed:
        click.echo(f"{label}Removed {len(result.removed)} blank secret(s): {', '.join(result.removed)}")
    else:
        click.echo(f"{label}No blank secrets found in '{environment}'.")
    click.echo(f"Kept: {result.kept}")
