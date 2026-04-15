"""CLI commands for comparing secrets across environments."""
from __future__ import annotations

import json

import click

from envault.cli import _get_vault
from envault.compare import CompareError, compare_all, compare_secret


@click.group("compare")
def compare_group():
    """Compare secret values across environments."""


@compare_group.command("secret")
@click.argument("key")
@click.option("--env", "environments", multiple=True, required=True, help="Environments to compare (repeat flag).")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
@click.option("--output", type=click.Choice(["text", "json"]), default="text", show_default=True)
def secret_cmd(key, environments, vault_file, passphrase, output):
    """Compare a single secret KEY across environments."""
    try:
        vault = _get_vault(vault_file, passphrase)
        result = compare_secret(vault, key, list(environments), passphrase)
    except CompareError as exc:
        raise click.ClickException(str(exc))

    if output == "json":
        click.echo(json.dumps(result.to_dict(), indent=2))
    else:
        click.echo(f"Key: {result.key}  Status: {result.status}")
        for env, val in result.environments.items():
            display = "<missing>" if val is None else val
            click.echo(f"  {env}: {display}")


@compare_group.command("all")
@click.option("--env", "environments", multiple=True, required=True, help="Environments to compare (repeat flag).")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
@click.option("--output", type=click.Choice(["text", "json"]), default="text", show_default=True)
@click.option("--status-filter", type=click.Choice(["match", "mismatch", "missing", "all"]), default="all", show_default=True)
def all_cmd(environments, vault_file, passphrase, output, status_filter):
    """Compare all secrets across environments."""
    try:
        vault = _get_vault(vault_file, passphrase)
        results = compare_all(vault, list(environments), passphrase)
    except CompareError as exc:
        raise click.ClickException(str(exc))

    if status_filter != "all":
        results = [r for r in results if r.status == status_filter]

    if output == "json":
        click.echo(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        if not results:
            click.echo("No secrets found.")
            return
        for r in results:
            click.echo(f"{r.key}: {r.status}")
            for env, val in r.environments.items():
                display = "<missing>" if val is None else val
                click.echo(f"  {env}: {display}")
