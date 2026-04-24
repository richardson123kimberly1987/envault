"""CLI commands for the pipeline feature."""
from __future__ import annotations

import click

from envault.cli import _get_vault
from envault.pipeline import PipelineError, PipelineStep, run_pipeline, run_pipeline_all

_BUILTIN_STEPS = {
    "upper": str.upper,
    "lower": str.lower,
    "strip": str.strip,
    "lstrip": str.lstrip,
    "rstrip": str.rstrip,
}


@click.group("pipeline")
def pipeline_group() -> None:
    """Chain transformation steps on secret values."""


@pipeline_group.command("run")
@click.argument("environment")
@click.argument("key")
@click.option(
    "--step",
    "steps",
    multiple=True,
    required=True,
    type=click.Choice(list(_BUILTIN_STEPS)),
    help="Transformation step to apply (repeatable).",
)
@click.option("--dry-run", is_flag=True, help="Preview result without saving.")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
def run_cmd(
    environment: str,
    key: str,
    steps: tuple,
    dry_run: bool,
    vault_file: str,
    passphrase: str,
) -> None:
    """Apply transformation steps to a single secret."""
    vault = _get_vault(vault_file, passphrase)
    pipeline_steps = [PipelineStep(s, _BUILTIN_STEPS[s]) for s in steps]
    try:
        result = run_pipeline(vault, environment, key, pipeline_steps, dry_run=dry_run)
    except PipelineError as exc:
        raise click.ClickException(str(exc)) from exc

    tag = " [dry-run]" if dry_run else ""
    click.echo(f"{key}: '{result.original}' -> '{result.final}'{tag}")
    click.echo(f"Steps applied: {', '.join(result.steps_applied)}")


@pipeline_group.command("run-all")
@click.argument("environment")
@click.option(
    "--step",
    "steps",
    multiple=True,
    required=True,
    type=click.Choice(list(_BUILTIN_STEPS)),
    help="Transformation step to apply (repeatable).",
)
@click.option("--dry-run", is_flag=True)
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
def run_all_cmd(
    environment: str,
    steps: tuple,
    dry_run: bool,
    vault_file: str,
    passphrase: str,
) -> None:
    """Apply transformation steps to all secrets in an environment."""
    vault = _get_vault(vault_file, passphrase)
    pipeline_steps = [PipelineStep(s, _BUILTIN_STEPS[s]) for s in steps]
    try:
        results = run_pipeline_all(vault, environment, pipeline_steps, dry_run=dry_run)
    except PipelineError as exc:
        raise click.ClickException(str(exc)) from exc

    tag = " [dry-run]" if dry_run else ""
    for r in results:
        click.echo(f"{r.key}: '{r.original}' -> '{r.final}'{tag}")
    click.echo(f"Processed {len(results)} secret(s).")
