"""CLI commands for the splice feature."""
from __future__ import annotations

import json

import click

from envault.splice import SpliceError, splice_secret


@click.group("splice")
def splice_group() -> None:
    """Insert or replace a segment within a secret value."""


@splice_group.command("run")
@click.argument("environment")
@click.argument("secret")
@click.option("--start", required=True, type=int, help="Start index (inclusive).")
@click.option("--end", required=True, type=int, help="End index (exclusive).")
@click.option("--replacement", required=True, help="Text to insert in place of the removed segment.")
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--json", "as_json", is_flag=True, default=False)
@click.pass_context
def run_cmd(
    ctx: click.Context,
    environment: str,
    secret: str,
    start: int,
    end: int,
    replacement: str,
    passphrase: str,
    vault_file: str,
    as_json: bool,
) -> None:
    """Splice REPLACEMENT into SECRET[START:END] within ENVIRONMENT."""
    from envault.vault import Vault

    vault = Vault(vault_file)
    vault.load(passphrase)

    try:
        result = splice_secret(vault, environment, secret, start, end, replacement, passphrase)
    except SpliceError as exc:
        click.echo(f"Error: {exc}", err=True)
        ctx.exit(1)
        return

    vault.save(passphrase)

    if as_json:
        click.echo(json.dumps(result.to_dict(), indent=2))
    else:
        click.echo(
            f"Spliced '{secret}' in '{environment}': "
            f"[{start}:{end}] -> '{replacement}'"
        )
        click.echo(f"  Before: {result.original}")
        click.echo(f"  After : {result.spliced}")
