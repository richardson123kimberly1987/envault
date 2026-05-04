"""CLI commands for the format feature."""
from __future__ import annotations

import json

import click

from envault.format import FORMAT_RULES, FormatError, format_all, format_secret


@click.group("format")
def format_group() -> None:
    """Format secret values (uppercase, lowercase, strip, truncate, capitalize)."""


@format_group.command("secret")
@click.argument("environment")
@click.argument("secret")
@click.option(
    "--rule",
    "rules",
    multiple=True,
    required=True,
    type=click.Choice(FORMAT_RULES),
    help="Formatting rule to apply (repeatable).",
)
@click.option("--truncate-len", default=64, show_default=True, help="Max length for truncate rule.")
@click.option("--json", "as_json", is_flag=True, help="Output result as JSON.")
@click.pass_context
def secret_cmd(ctx: click.Context, environment: str, secret: str, rules: tuple, truncate_len: int, as_json: bool) -> None:
    """Apply format rules to a single secret."""
    vault = ctx.obj["vault"]
    try:
        result = format_secret(vault, environment, secret, list(rules), truncate_len)
    except FormatError as exc:
        click.echo(f"Error: {exc}", err=True)
        ctx.exit(1)
        return
    if as_json:
        click.echo(json.dumps(result.to_dict(), indent=2))
    else:
        click.echo(
            f"Formatted {result.secret!r} in {result.environment!r}: "
            f"{result.original!r} -> {result.formatted!r} "
            f"(rules: {', '.join(result.rules_applied)})"
        )


@format_group.command("all")
@click.argument("environment")
@click.option(
    "--rule",
    "rules",
    multiple=True,
    required=True,
    type=click.Choice(FORMAT_RULES),
    help="Formatting rule to apply (repeatable).",
)
@click.option("--truncate-len", default=64, show_default=True, help="Max length for truncate rule.")
@click.option("--json", "as_json", is_flag=True, help="Output results as JSON.")
@click.pass_context
def all_cmd(ctx: click.Context, environment: str, rules: tuple, truncate_len: int, as_json: bool) -> None:
    """Apply format rules to all secrets in an environment."""
    vault = ctx.obj["vault"]
    try:
        results = format_all(vault, environment, list(rules), truncate_len)
    except FormatError as exc:
        click.echo(f"Error: {exc}", err=True)
        ctx.exit(1)
        return
    if as_json:
        click.echo(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        if not results:
            click.echo(f"No secrets found in environment {environment!r}.")
            return
        for r in results:
            click.echo(f"  {r.secret}: {r.original!r} -> {r.formatted!r}")
        click.echo(f"Formatted {len(results)} secret(s) with rules: {', '.join(rules)}.")
