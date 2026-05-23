"""CLI commands for the pivot feature."""
from __future__ import annotations

import json

import click

from envault.pivot import PivotError, pivot_environment


@click.group("pivot")
def pivot_group() -> None:
    """Reorganise secrets by grouping keys that share the same value."""


@pivot_group.command("run")
@click.argument("environment")
@click.option("--target", default=None, help="Optional second environment to intersect with.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Output as JSON.")
@click.option("--vault-file", envvar="ENVAULT_VAULT_FILE", default="vault.json", show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
def run_cmd(environment: str, target: str | None, as_json: bool, vault_file: str, passphrase: str) -> None:
    """Pivot secrets in ENVIRONMENT, grouping keys by shared value."""
    from envault.vault import Vault, VaultError

    try:
        vault = Vault(vault_file, passphrase)
        vault.load()
    except VaultError as exc:
        click.echo(f"Vault error: {exc}", err=True)
        raise SystemExit(1)

    try:
        result = pivot_environment(vault, environment, target_env=target)
    except PivotError as exc:
        click.echo(f"Pivot error: {exc}", err=True)
        raise SystemExit(1)

    if as_json:
        click.echo(json.dumps(result.to_dict(), indent=2))
        return

    if result.total == 0:
        click.echo("No pivot entries found.")
        return

    click.echo(f"Pivot of '{environment}' ({result.total} unique value(s)):\n")
    for value, entry in result.pivoted.items():
        masked = value[:4] + "****" if len(value) > 4 else "****"
        envs = ", ".join(entry.environments)
        click.echo(f"  {masked}  →  environments: [{envs}]")
