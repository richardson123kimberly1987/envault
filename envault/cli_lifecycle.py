"""CLI commands for lifecycle management of secrets."""
from __future__ import annotations

import click

from envault.lifecycle import LifecycleError, LIFECYCLE_STAGES, set_stage, get_stage, list_by_stage


@click.group("lifecycle")
def lifecycle_group():
    """Manage secret lifecycle stages."""


@lifecycle_group.command("set")
@click.argument("environment")
@click.argument("secret")
@click.argument("stage", type=click.Choice(LIFECYCLE_STAGES))
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
def set_cmd(environment, secret, stage, vault_file, passphrase):
    """Set the lifecycle STAGE for a secret."""
    from envault.cli import _get_vault
    vault = _get_vault(vault_file, passphrase)
    try:
        result = set_stage(vault, environment, secret, stage)
        vault.save()
        click.echo(
            f"[lifecycle] {secret} in '{environment}': "
            f"{result.previous_stage} -> {result.current_stage}"
        )
    except LifecycleError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)


@lifecycle_group.command("get")
@click.argument("environment")
@click.argument("secret")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
def get_cmd(environment, secret, vault_file, passphrase):
    """Get the current lifecycle stage of a secret."""
    from envault.cli import _get_vault
    vault = _get_vault(vault_file, passphrase)
    try:
        stage = get_stage(vault, environment, secret)
        click.echo(f"{secret}: {stage}")
    except LifecycleError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)


@lifecycle_group.command("list")
@click.argument("environment")
@click.argument("stage", type=click.Choice(LIFECYCLE_STAGES))
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
def list_cmd(environment, stage, vault_file, passphrase):
    """List all secrets in a given lifecycle STAGE."""
    from envault.cli import _get_vault
    vault = _get_vault(vault_file, passphrase)
    try:
        names = list_by_stage(vault, environment, stage)
        if not names:
            click.echo(f"No secrets in stage '{stage}'.")
        else:
            for name in names:
                click.echo(name)
    except LifecycleError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)
