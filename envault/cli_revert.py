"""CLI commands for reverting secrets to previous history entries."""
from __future__ import annotations

import click

from envault.cli import _get_vault, _get_audit
from envault.revert import RevertError, revert_secret


@click.group("revert")
def revert_group() -> None:
    """Revert secrets to a previous value."""


@revert_group.command("secret")
@click.argument("environment")
@click.argument("secret")
@click.option(
    "--index",
    "-i",
    default=-1,
    show_default=True,
    help="History index to revert to (negative indices count from the end).",
)
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--audit-file", default="audit.log", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
def secret_cmd(
    environment: str,
    secret: str,
    index: int,
    vault_file: str,
    audit_file: str,
    passphrase: str,
) -> None:
    """Revert SECRET in ENVIRONMENT to a previous history entry."""
    vault = _get_vault(vault_file, passphrase)
    audit = _get_audit(audit_file)

    try:
        result = revert_secret(vault, environment, secret, index=index)
    except RevertError as exc:
        raise click.ClickException(str(exc)) from exc

    audit.record(
        event="revert",
        details=result.to_dict(),
    )

    click.echo(
        f"Reverted '{secret}' in '{environment}' "
        f"to value from {result.reverted_to!r}."
    )
