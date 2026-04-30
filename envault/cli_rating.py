"""CLI commands for the secret rating feature."""
from __future__ import annotations

import json

import click

from envault.cli import _get_vault
from envault.rating import RATING_LEVELS, RatingError, rate_all, rate_secret


@click.group("rating")
def rating_group() -> None:
    """Rate secrets by quality."""


@rating_group.command("score")
@click.argument("environment")
@click.argument("secret_name")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
@click.option("--json", "as_json", is_flag=True, default=False, help="Output as JSON")
def score_cmd(environment: str, secret_name: str, vault_file: str, passphrase: str, as_json: bool) -> None:
    """Rate a single secret."""
    vault = _get_vault(vault_file, passphrase)
    try:
        result = rate_secret(vault, environment, secret_name)
    except RatingError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)

    if as_json:
        click.echo(json.dumps(result.to_dict(), indent=2))
    else:
        click.echo(f"Secret : {result.secret_name}")
        click.echo(f"Env    : {result.environment}")
        click.echo(f"Score  : {result.score}/100")
        click.echo(f"Level  : {result.level}")
        for factor, val in result.factors.items():
            click.echo(f"  {factor}: {val}")


@rating_group.command("all")
@click.argument("environment")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
@click.option("--min-level", default=None, type=click.Choice(RATING_LEVELS), help="Filter by minimum level")
@click.option("--json", "as_json", is_flag=True, default=False, help="Output as JSON")
def all_cmd(environment: str, vault_file: str, passphrase: str, min_level: str | None, as_json: bool) -> None:
    """Rate all secrets in an environment."""
    vault = _get_vault(vault_file, passphrase)
    results = rate_all(vault, environment)

    if min_level is not None:
        threshold = RATING_LEVELS.index(min_level)
        results = [r for r in results if RATING_LEVELS.index(r.level) >= threshold]

    if as_json:
        click.echo(json.dumps([r.to_dict() for r in results], indent=2))
        return

    if not results:
        click.echo("No secrets found.")
        return

    for r in results:
        click.echo(f"{r.secret_name:30s}  {r.score:3d}/100  [{r.level}]")
