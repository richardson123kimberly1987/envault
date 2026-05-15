"""CLI commands for secret version tracking."""
from __future__ import annotations

import json

import click

from envault.cli import _get_vault
from envault.version import VersionError, bump_version, get_version, list_versions


@click.group("version")
def version_group() -> None:
    """Track and inspect secret version numbers."""


@version_group.command("bump")
@click.argument("environment")
@click.argument("secret")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
@click.option("--json", "as_json", is_flag=True, default=False)
def bump_cmd(environment: str, secret: str, vault_file: str, passphrase: str, as_json: bool) -> None:
    """Bump the version counter for SECRET in ENVIRONMENT."""
    vault = _get_vault(vault_file, passphrase)
    try:
        result = bump_version(vault, environment, secret)
        vault.save()
    except VersionError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)
    if as_json:
        click.echo(json.dumps(result.to_dict()))
    else:
        prev = result.previous if result.previous is not None else "(none)"
        click.echo(f"Bumped {secret} in {environment}: {prev} -> {result.version}")


@version_group.command("get")
@click.argument("environment")
@click.argument("secret")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
def get_cmd(environment: str, secret: str, vault_file: str, passphrase: str) -> None:
    """Print the current version number for SECRET in ENVIRONMENT."""
    vault = _get_vault(vault_file, passphrase)
    version = get_version(vault, environment, secret)
    click.echo(str(version))


@version_group.command("list")
@click.argument("environment")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
@click.option("--json", "as_json", is_flag=True, default=False)
def list_cmd(environment: str, vault_file: str, passphrase: str, as_json: bool) -> None:
    """List all versioned secrets in ENVIRONMENT."""
    vault = _get_vault(vault_file, passphrase)
    entries = list_versions(vault, environment)
    if as_json:
        click.echo(json.dumps(entries))
    else:
        if not entries:
            click.echo(f"No versioned secrets in '{environment}'.")
        else:
            for e in entries:
                click.echo(f"{e['secret']}: v{e['version']}")
