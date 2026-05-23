"""CLI commands for the chain feature."""
from __future__ import annotations

import json

import click

from envault.chain import CHAIN_STEPS, ChainError, chain_secret


@click.group("chain")
def chain_group() -> None:
    """Chain transformation steps on a secret value."""


@chain_group.command("run")
@click.argument("env")
@click.argument("secret")
@click.option(
    "--step",
    "steps",
    multiple=True,
    required=True,
    help="Transformation step to apply (repeatable, applied in order).",
)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
@click.option("--dry-run", is_flag=True, default=False, help="Do not persist the result.")
@click.option("--json", "as_json", is_flag=True, default=False)
@click.pass_context
def run_cmd(
    ctx: click.Context,
    env: str,
    secret: str,
    steps: tuple,
    passphrase: str,
    dry_run: bool,
    as_json: bool,
) -> None:
    """Apply one or more transformation steps to SECRET in ENV."""
    vault = ctx.obj["vault"]
    try:
        result = chain_secret(
            vault, env, secret, list(steps), passphrase, save=not dry_run
        )
    except ChainError as exc:
        click.echo(f"Error: {exc}", err=True)
        ctx.exit(1)
        return

    if as_json:
        click.echo(json.dumps(result.to_dict(), indent=2))
    else:
        label = " (dry-run)" if dry_run else ""
        click.echo(f"[chain{label}] {env}/{secret}: {result.result}")


@chain_group.command("steps")
def steps_cmd() -> None:
    """List available transformation steps."""
    for step in CHAIN_STEPS:
        click.echo(f"  {step}")
