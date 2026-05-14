"""CLI commands for the obfuscate feature."""
from __future__ import annotations

import json

import click

from envault.obfuscate import OBFUSCATE_STYLES, ObfuscateError, obfuscate_all, obfuscate_secret


@click.group("obfuscate", help="Obfuscate secret values for safe display.")
def obfuscate_group() -> None:
    pass


@obfuscate_group.command("secret")
@click.argument("environment")
@click.argument("key")
@click.option("--style", default="partial", show_default=True,
              type=click.Choice(OBFUSCATE_STYLES), help="Obfuscation style.")
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", default="", help="Vault passphrase.")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.pass_context
def secret_cmd(ctx: click.Context, environment: str, key: str, style: str, passphrase: str, as_json: bool) -> None:
    """Obfuscate a single secret."""
    vault = ctx.obj["vault"]
    try:
        result = obfuscate_secret(vault, environment, key, style, passphrase)
    except ObfuscateError as exc:
        click.echo(f"Error: {exc}", err=True)
        ctx.exit(1)
        return
    if as_json:
        click.echo(json.dumps(result.to_dict(), indent=2))
    else:
        click.echo(f"{result.key}={result.obfuscated}  (style={result.style}, length={result.original_length})")


@obfuscate_group.command("all")
@click.argument("environment")
@click.option("--style", default="partial", show_default=True,
              type=click.Choice(OBFUSCATE_STYLES), help="Obfuscation style.")
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", default="", help="Vault passphrase.")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.pass_context
def all_cmd(ctx: click.Context, environment: str, style: str, passphrase: str, as_json: bool) -> None:
    """Obfuscate all secrets in an environment."""
    vault = ctx.obj["vault"]
    try:
        results = obfuscate_all(vault, environment, style, passphrase)
    except ObfuscateError as exc:
        click.echo(f"Error: {exc}", err=True)
        ctx.exit(1)
        return
    if as_json:
        click.echo(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        for r in results:
            click.echo(f"{r.key}={r.obfuscated}")
