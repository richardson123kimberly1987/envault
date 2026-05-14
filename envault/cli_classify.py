"""CLI commands for secret classification."""
from __future__ import annotations

import json

import click

from envault.classify import (
    CLASSIFICATION_LEVELS,
    ClassifyError,
    get_classification,
    list_by_classification,
    set_classification,
)
from envault.cli import _get_vault


@click.group("classify")
def classify_group():
    """Manage secret classification levels."""


@classify_group.command("set")
@click.argument("environment")
@click.argument("secret")
@click.argument("level", type=click.Choice(CLASSIFICATION_LEVELS))
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
def set_cmd(environment, secret, level, vault_file, passphrase):
    """Set the classification level for a secret."""
    vault = _get_vault(vault_file, passphrase)
    try:
        result = set_classification(vault, environment, secret, level)
        vault.save()
        prev = f" (was: {result.previous})" if result.previous else ""
        click.echo(f"Classified '{secret}' as '{level}'{prev}.")
    except ClassifyError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)


@classify_group.command("get")
@click.argument("environment")
@click.argument("secret")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
@click.option("--json", "as_json", is_flag=True, default=False)
def get_cmd(environment, secret, vault_file, passphrase, as_json):
    """Get the classification level of a secret."""
    vault = _get_vault(vault_file, passphrase)
    try:
        result = get_classification(vault, environment, secret)
        if as_json:
            click.echo(json.dumps(result.to_dict(), indent=2))
        else:
            click.echo(f"{result.secret}: {result.level}")
    except ClassifyError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)


@classify_group.command("list")
@click.argument("environment")
@click.argument("level", type=click.Choice(CLASSIFICATION_LEVELS))
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
@click.option("--json", "as_json", is_flag=True, default=False)
def list_cmd(environment, level, vault_file, passphrase, as_json):
    """List secrets with a given classification level."""
    vault = _get_vault(vault_file, passphrase)
    try:
        results = list_by_classification(vault, environment, level)
        if as_json:
            click.echo(json.dumps([r.to_dict() for r in results], indent=2))
        else:
            if not results:
                click.echo(f"No secrets classified as '{level}' in '{environment}'.")
            for r in results:
                click.echo(f"  {r.secret}")
    except ClassifyError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)
