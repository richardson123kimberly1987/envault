"""CLI commands for environment secret inheritance."""
from __future__ import annotations

import click

from envault.cli import _get_vault
from envault.inherit import InheritError, inherit_environment


@click.group("inherit", help="Propagate secrets from one environment to another.")
def inherit_group() -> None:
    pass


@inherit_group.command("run")
@click.argument("base_env")
@click.argument("target_env")
@click.option(
    "--overwrite",
    is_flag=True,
    default=False,
    help="Overwrite secrets that already exist in the target environment.",
)
@click.option(
    "--key",
    "keys",
    multiple=True,
    metavar="KEY",
    help="Restrict inheritance to specific keys (repeatable).",
)
@click.option("--vault-file", default="vault.json", show_default=True, help="Path to vault file.")
@click.option("--passphrase", prompt=True, hide_input=True, help="Vault passphrase.")
def run_cmd(
    base_env: str,
    target_env: str,
    overwrite: bool,
    keys: tuple,
    vault_file: str,
    passphrase: str,
) -> None:
    """Copy secrets from BASE_ENV into TARGET_ENV."""
    vault = _get_vault(vault_file, passphrase)
    try:
        result = inherit_environment(
            vault,
            base_env=base_env,
            target_env=target_env,
            overwrite=overwrite,
            keys=list(keys) if keys else None,
        )
    except InheritError as exc:
        raise click.ClickException(str(exc)) from exc

    if result.inherited:
        click.echo(f"Inherited ({len(result.inherited)}): {', '.join(result.inherited)}")
    else:
        click.echo("No secrets were inherited.")

    if result.skipped:
        click.echo(
            f"Skipped ({len(result.skipped)}) — already exist in '{target_env}': "
            f"{', '.join(result.skipped)}"
        )
