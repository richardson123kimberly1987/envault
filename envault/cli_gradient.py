"""CLI commands for the gradient sensitivity feature."""
from __future__ import annotations

import json

import click

from .gradient import GradientError, compute_gradient, compute_gradient_all


@click.group("gradient")
def gradient_group() -> None:
    """Sensitivity gradient scoring for secrets."""


@gradient_group.command("score")
@click.argument("environment")
@click.argument("secret")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.pass_context
def score_cmd(ctx: click.Context, environment: str, secret: str, as_json: bool) -> None:
    """Show the gradient score for a single SECRET in ENVIRONMENT."""
    vault = ctx.obj["vault"]
    try:
        result = compute_gradient(vault, environment, secret)
    except GradientError as exc:
        click.echo(f"Error: {exc}", err=True)
        ctx.exit(1)
        return

    if as_json:
        click.echo(json.dumps(result.to_dict(), indent=2))
    else:
        click.echo(f"Secret    : {result.secret}")
        click.echo(f"Environment: {result.environment}")
        click.echo(f"Score     : {result.score:.4f}")
        click.echo(f"Level     : {result.level}")
        click.echo("Dimensions:")
        for dim, val in result.dimensions.items():
            click.echo(f"  {dim:<16} {val:.4f}")


@gradient_group.command("all")
@click.argument("environment")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.option(
    "--min-level",
    default=None,
    type=click.Choice(["negligible", "low", "medium", "high", "critical"]),
    help="Only show secrets at or above this level.",
)
@click.pass_context
def all_cmd(
    ctx: click.Context, environment: str, as_json: bool, min_level: str | None
) -> None:
    """Show gradient scores for all secrets in ENVIRONMENT."""
    vault = ctx.obj["vault"]
    from .gradient import GRADIENT_LEVELS  # noqa: PLC0415

    results = compute_gradient_all(vault, environment)

    if min_level:
        threshold = GRADIENT_LEVELS.index(min_level)
        results = [r for r in results if GRADIENT_LEVELS.index(r.level) >= threshold]

    if as_json:
        click.echo(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        if not results:
            click.echo("No secrets found.")
            return
        click.echo(f"{'Secret':<30} {'Score':>8}  Level")
        click.echo("-" * 50)
        for r in results:
            click.echo(f"{r.secret:<30} {r.score:>8.4f}  {r.level}")
