"""CLI commands for vault summarization."""
from __future__ import annotations

import json

import click

from envault.summarize import SummarizeError, summarize_all, summarize_environment


@click.group("summarize")
def summarize_group() -> None:
    """Summarize secrets across environments."""


@summarize_group.command("env")
@click.argument("environment")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
@click.option("--json", "as_json", is_flag=True, default=False)
def env_cmd(environment: str, vault_file: str, passphrase: str, as_json: bool) -> None:
    """Summarize secrets in ENVIRONMENT."""
    from envault.cli import _get_vault

    vault = _get_vault(vault_file, passphrase)
    try:
        result = summarize_environment(vault, environment)
    except SummarizeError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)

    if as_json:
        click.echo(json.dumps(result.to_dict(), indent=2))
    else:
        click.echo(f"Environment : {result.environment}")
        click.echo(f"Total       : {result.total}")
        click.echo(f"Has expiry  : {result.has_expiry}")
        click.echo(f"Locked      : {result.locked}")
        click.echo(f"Tagged      : {result.tagged}")


@summarize_group.command("all")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
@click.option("--json", "as_json", is_flag=True, default=False)
def all_cmd(vault_file: str, passphrase: str, as_json: bool) -> None:
    """Summarize secrets across all environments."""
    from envault.cli import _get_vault

    vault = _get_vault(vault_file, passphrase)
    results = summarize_all(vault)

    if as_json:
        click.echo(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        for result in results:
            click.echo(
                f"{result.environment}: {result.total} secrets "
                f"({result.has_expiry} expiring, {result.locked} locked, {result.tagged} tagged)"
            )
