"""CLI entry point for envault."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from envault.vault import Vault, VaultError
from envault.audit import AuditLog

DEFAULT_VAULT = Path(".envault/vault.json")
DEFAULT_AUDIT_LOG = Path(".envault/audit.log")


def _get_vault(vault_path: Path, passphrase: str) -> Vault:
    return Vault(vault_path, passphrase)


def _get_audit(audit_path: Path) -> AuditLog:
    return AuditLog(audit_path)


@click.group()
@click.option("--vault", default=str(DEFAULT_VAULT), show_default=True, help="Path to vault file.")
@click.option("--audit-log", default=str(DEFAULT_AUDIT_LOG), show_default=True, help="Path to audit log.")
@click.pass_context
def cli(ctx: click.Context, vault: str, audit_log: str) -> None:
    """envault — secure environment variable management."""
    ctx.ensure_object(dict)
    ctx.obj["vault_path"] = Path(vault)
    ctx.obj["audit_path"] = Path(audit_log)


@cli.command("set")
@click.argument("key")
@click.argument("value")
@click.option("--env", default="default", show_default=True, help="Target environment.")
@click.option("--passphrase", prompt=True, hide_input=True)
@click.pass_context
def set_secret(ctx: click.Context, key: str, value: str, env: str, passphrase: str) -> None:
    """Set a secret KEY to VALUE in the vault."""
    vault = _get_vault(ctx.obj["vault_path"], passphrase)
    vault.set(key, value, environment=env)
    vault.save()
    _get_audit(ctx.obj["audit_path"]).record("set", key, env)
    click.echo(f"Secret '{key}' set in environment '{env}'.")


@cli.command("get")
@click.argument("key")
@click.option("--env", default="default", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
@click.pass_context
def get_secret(ctx: click.Context, key: str, env: str, passphrase: str) -> None:
    """Get a secret KEY from the vault."""
    vault = _get_vault(ctx.obj["vault_path"], passphrase)
    value = vault.get(key, environment=env)
    if value is None:
        click.echo(f"Secret '{key}' not found in environment '{env}'.", err=True)
        sys.exit(1)
    _get_audit(ctx.obj["audit_path"]).record("get", key, env)
    click.echo(value)


@cli.command("delete")
@click.argument("key")
@click.option("--env", default="default", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
@click.pass_context
def delete_secret(ctx: click.Context, key: str, env: str, passphrase: str) -> None:
    """Delete a secret KEY from the vault."""
    vault = _get_vault(ctx.obj["vault_path"], passphrase)
    vault.delete(key, environment=env)
    vault.save()
    _get_audit(ctx.obj["audit_path"]).record("delete", key, env)
    click.echo(f"Secret '{key}' deleted from environment '{env}'.")


@cli.command("audit")
@click.option("--env", default=None, help="Filter by environment.")
@click.option("--event", default=None, help="Filter by event type.")
@click.option("--audit-log", default=str(DEFAULT_AUDIT_LOG), show_default=True)
@click.pass_context
def show_audit(ctx: click.Context, env: str, event: str, audit_log: str) -> None:
    """Display the audit log."""
    log = AuditLog(Path(audit_log))
    entries = log.read(environment=env, event=event)
    if not entries:
        click.echo("No audit entries found.")
        return
    for entry in entries:
        meta = f" {entry.metadata}" if entry.metadata else ""
        click.echo(f"[{entry.timestamp}] {entry.actor} {entry.event} {entry.key} ({entry.environment}){meta}")
