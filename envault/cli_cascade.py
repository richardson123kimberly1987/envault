"""CLI commands for the cascade feature."""
from __future__ import annotations

import click

from .cascade import CascadeError, cascade_all, cascade_secret


@click.group("cascade")
def cascade_group() -> None:
    """Propagate secrets from one environment to others."""


@cascade_group.command("secret")
@click.argument("secret_name")
@click.option("--from", "source_env", required=True, help="Source environment.")
@click.option(
    "--to",
    "target_envs",
    required=True,
    multiple=True,
    help="Target environment(s). May be repeated.",
)
@click.option(
    "--overwrite",
    is_flag=True,
    default=False,
    help="Overwrite existing secrets in target environments.",
)
@click.pass_context
def secret_cmd(ctx, secret_name, source_env, target_envs, overwrite):
    """Cascade a single secret from SOURCE_ENV to one or more target envs."""
    vault = ctx.obj["vault"]
    try:
        result = cascade_secret(
            vault, secret_name, source_env, list(target_envs), overwrite=overwrite
        )
    except CascadeError as exc:
        raise click.ClickException(str(exc)) from exc

    vault.save()
    if result.propagated_to:
        click.echo(
            f"Cascaded '{secret_name}' to: {', '.join(result.propagated_to)}"
        )
    if result.skipped:
        click.echo(
            f"Skipped (already exists, use --overwrite): {', '.join(result.skipped)}"
        )


@cascade_group.command("all")
@click.option("--from", "source_env", required=True, help="Source environment.")
@click.option(
    "--to",
    "target_envs",
    required=True,
    multiple=True,
    help="Target environment(s). May be repeated.",
)
@click.option(
    "--overwrite",
    is_flag=True,
    default=False,
    help="Overwrite existing secrets in target environments.",
)
@click.pass_context
def all_cmd(ctx, source_env, target_envs, overwrite):
    """Cascade ALL secrets from SOURCE_ENV to one or more target envs."""
    vault = ctx.obj["vault"]
    try:
        results = cascade_all(
            vault, source_env, list(target_envs), overwrite=overwrite
        )
    except CascadeError as exc:
        raise click.ClickException(str(exc)) from exc

    vault.save()
    total_propagated = sum(len(r.propagated_to) for r in results)
    total_skipped = sum(len(r.skipped) for r in results)
    click.echo(
        f"Cascade complete: {total_propagated} propagated, {total_skipped} skipped."
    )
