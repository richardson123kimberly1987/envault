"""CLI commands for suffix management."""
from __future__ import annotations

import json

import click

from envault.suffix import SuffixError, add_suffix, remove_suffix, list_with_suffix


@click.group(name="suffix")
def suffix_group():
    """Manage secret key suffixes."""


@suffix_group.command(name="add")
@click.argument("environment")
@click.argument("secret")
@click.argument("suffix")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--json", "as_json", is_flag=True, default=False)
@click.pass_context
def add_cmd(ctx, environment: str, secret: str, suffix: str, vault_file: str, as_json: bool):
    """Append SUFFIX to a secret key, renaming it."""
    from envault.cli import _get_vault

    vault = _get_vault(vault_file)
    try:
        result = add_suffix(vault, environment, secret, suffix)
        vault.save()
    except SuffixError as exc:
        click.echo(f"Error: {exc}", err=True)
        ctx.exit(1)
        return

    if as_json:
        click.echo(json.dumps(result.to_dict(), indent=2))
    else:
        click.echo(f"Renamed '{result.old_key}' -> '{result.new_key}' in [{environment}]")


@suffix_group.command(name="remove")
@click.argument("environment")
@click.argument("secret")
@click.argument("suffix")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--json", "as_json", is_flag=True, default=False)
@click.pass_context
def remove_cmd(ctx, environment: str, secret: str, suffix: str, vault_file: str, as_json: bool):
    """Strip SUFFIX from a secret key, renaming it."""
    from envault.cli import _get_vault

    vault = _get_vault(vault_file)
    try:
        result = remove_suffix(vault, environment, secret, suffix)
        vault.save()
    except SuffixError as exc:
        click.echo(f"Error: {exc}", err=True)
        ctx.exit(1)
        return

    if as_json:
        click.echo(json.dumps(result.to_dict(), indent=2))
    else:
        click.echo(f"Renamed '{result.old_key}' -> '{result.new_key}' in [{environment}]")


@suffix_group.command(name="list")
@click.argument("environment")
@click.argument("suffix")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--json", "as_json", is_flag=True, default=False)
@click.pass_context
def list_cmd(ctx, environment: str, suffix: str, vault_file: str, as_json: bool):
    """List secrets whose keys end with SUFFIX."""
    from envault.cli import _get_vault

    vault = _get_vault(vault_file)
    try:
        keys = list_with_suffix(vault, environment, suffix)
    except SuffixError as exc:
        click.echo(f"Error: {exc}", err=True)
        ctx.exit(1)
        return

    if as_json:
        click.echo(json.dumps(keys))
    else:
        if keys:
            for k in keys:
                click.echo(k)
        else:
            click.echo(f"No secrets ending with '{suffix}' in [{environment}]")
