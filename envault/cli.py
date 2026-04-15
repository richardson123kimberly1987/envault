"""Main CLI entry point for envault."""

from __future__ import annotations

from pathlib import Path

import click

from envault.audit import AuditLog
from envault.vault import Vault, VaultError
from envault.cli_snapshot import snapshot_group
from envault.cli_tags import tag_group
from envault.cli_access import access_group

_DEFAULT_VAULT = Path(".envault.json")
_DEFAULT_AUDIT = Path(".envault_audit.jsonl")


def _get_vault(path: Path, passphrase: str) -> Vault:
    vault = Vault(path=path, passphrase=passphrase)
    vault.load()
    return vault


def _get_audit(path: Path) -> AuditLog:
    return AuditLog(path=path)


@click.group()
def cli() -> None:
    """envault — secure environment variable management."""


@cli.command()
@click.argument("key")
@click.argument("value")
@click.option("--env", "environment", default="default", show_default=True)
@click.option("--vault", "vault_path", default=str(_DEFAULT_VAULT), show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
def set_secret(
    key: str,
    value: str,
    environment: str,
    vault_path: str,
    passphrase: str,
) -> None:
    """Set a secret KEY to VALUE in the vault."""
    try:
        vault = _get_vault(Path(vault_path), passphrase)
        vault.set_secret(environment, key, value)
        vault.save()
        audit = _get_audit(_DEFAULT_AUDIT)
        audit.record("set_secret", {"key": key, "environment": environment})
        click.echo(f"Secret '{key}' set in environment '{environment}'.")
    except VaultError as exc:
        raise click.ClickException(str(exc)) from exc


@cli.command()
@click.argument("key")
@click.option("--env", "environment", default="default", show_default=True)
@click.option("--vault", "vault_path", default=str(_DEFAULT_VAULT), show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
def get_secret(
    key: str,
    environment: str,
    vault_path: str,
    passphrase: str,
) -> None:
    """Get a secret by KEY from the vault."""
    try:
        vault = _get_vault(Path(vault_path), passphrase)
        entry = vault.get_secret(environment, key)
        if entry is None:
            click.echo(f"Secret '{key}' not found in environment '{environment}'.")
        else:
            click.echo(entry.value)
    except VaultError as exc:
        raise click.ClickException(str(exc)) from exc


@cli.command(name="list")
@click.option("--env", "environment", default="default", show_default=True)
@click.option("--vault", "vault_path", default=str(_DEFAULT_VAULT), show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
def list_secrets(
    environment: str,
    vault_path: str,
    passphrase: str,
) -> None:
    """List all secret keys in the given environment."""
    try:
        vault = _get_vault(Path(vault_path), passphrase)
        keys = vault.list_secrets(environment)
        if not keys:
            click.echo(f"No secrets in environment '{environment}'.")
        else:
            for k in keys:
                click.echo(k)
    except VaultError as exc:
        raise click.ClickException(str(exc)) from exc


cli.add_command(snapshot_group, name="snapshot")
cli.add_command(tag_group, name="tag")
cli.add_command(access_group, name="access")
