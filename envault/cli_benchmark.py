"""CLI commands for benchmarking secret operations."""
from __future__ import annotations

import json

import click

from envault.benchmark import benchmark_secret, benchmark_all, BENCHMARK_OPERATIONS, BenchmarkError


@click.group("benchmark")
def benchmark_group() -> None:
    """Benchmark secret encryption/decryption performance."""


@benchmark_group.command("run")
@click.argument("key")
@click.option("--env", default="default", show_default=True, help="Environment name.")
@click.option(
    "--operation",
    default="encrypt",
    show_default=True,
    type=click.Choice(BENCHMARK_OPERATIONS),
    help="Operation to benchmark.",
)
@click.option("--iterations", default=100, show_default=True, help="Number of iterations.")
@click.option("--passphrase", default="", help="Passphrase for crypto operations.")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.pass_context
def run_cmd(
    ctx: click.Context,
    key: str,
    env: str,
    operation: str,
    iterations: int,
    passphrase: str,
    as_json: bool,
) -> None:
    """Benchmark a single secret operation."""
    vault = ctx.obj["vault"]
    try:
        result = benchmark_secret(vault, key, env, operation, iterations, passphrase)
    except BenchmarkError as exc:
        raise click.ClickException(str(exc)) from exc

    if as_json:
        click.echo(json.dumps(result.to_dict(), indent=2))
    else:
        click.echo(f"Operation : {result.operation}")
        click.echo(f"Key       : {result.secret_key} ({result.environment})")
        click.echo(f"Iterations: {result.iterations}")
        click.echo(f"Total     : {result.total_seconds:.4f}s")
        click.echo(f"Avg       : {result.avg_seconds * 1000:.4f}ms")
        click.echo(f"Min       : {result.min_seconds * 1000:.4f}ms")
        click.echo(f"Max       : {result.max_seconds * 1000:.4f}ms")


@benchmark_group.command("all")
@click.option("--env", default="default", show_default=True, help="Environment name.")
@click.option(
    "--operation",
    default="encrypt",
    show_default=True,
    type=click.Choice(BENCHMARK_OPERATIONS),
    help="Operation to benchmark.",
)
@click.option("--iterations", default=50, show_default=True, help="Number of iterations.")
@click.option("--passphrase", default="", help="Passphrase for crypto operations.")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.pass_context
def all_cmd(
    ctx: click.Context,
    env: str,
    operation: str,
    iterations: int,
    passphrase: str,
    as_json: bool,
) -> None:
    """Benchmark an operation across all secrets in an environment."""
    vault = ctx.obj["vault"]
    results = benchmark_all(vault, env, operation, iterations, passphrase)
    if not results:
        click.echo("No secrets found to benchmark.")
        return
    if as_json:
        click.echo(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        click.echo(f"{'Key':<30} {'Avg (ms)':>12} {'Min (ms)':>12} {'Max (ms)':>12}")
        click.echo("-" * 70)
        for r in results:
            click.echo(
                f"{r.secret_key:<30} "
                f"{r.avg_seconds * 1000:>12.4f} "
                f"{r.min_seconds * 1000:>12.4f} "
                f"{r.max_seconds * 1000:>12.4f}"
            )
