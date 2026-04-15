"""CLI commands for secret expiry management."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import click

from envault.cli import _get_vault, _get_audit
from envault.expiry import (
    EXPIRY_DATE_FORMAT,
    ExpiryError,
    check_expiry,
    list_expiring,
    set_expiry,
)


@click.group("expiry")
def expiry_group():
    """Manage secret expiry and TTL."""


@expiry_group.command("set")
@click.option("--vault", "vault_path", required=True, envvar="ENVAULT_VAULT", help="Path to vault file.")
@click.option("--passphrase", required=True, envvar="ENVAULT_PASSPHRASE", hide_input=True, help="Vault passphrase.")
@click.option("--env", "environment", required=True, help="Target environment.")
@click.option("--key", required=True, help="Secret key.")
@click.option("--days", type=int, default=None, help="Expire in N days from now.")
@click.option("--date", "expires_at", default=None, help=f"Explicit expiry date ({EXPIRY_DATE_FORMAT}).")
def set_cmd(vault_path, passphrase, environment, key, days, expires_at):
    """Set an expiry date on a secret."""
    if days is None and expires_at is None:
        raise click.UsageError("Provide --days or --date.")
    if days is not None:
        expires_at = (datetime.now(timezone.utc) + timedelta(days=days)).strftime(EXPIRY_DATE_FORMAT)
    vault = _get_vault(vault_path, passphrase)
    try:
        result = set_expiry(vault, environment, key, expires_at)
        vault.save()
    except ExpiryError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Expiry set: {key} expires at {result.expires_at}")


@expiry_group.command("check")
@click.option("--vault", "vault_path", required=True, envvar="ENVAULT_VAULT", help="Path to vault file.")
@click.option("--passphrase", required=True, envvar="ENVAULT_PASSPHRASE", hide_input=True, help="Vault passphrase.")
@click.option("--env", "environment", required=True, help="Target environment.")
@click.option("--key", required=True, help="Secret key.")
def check_cmd(vault_path, passphrase, environment, key):
    """Check the expiry status of a secret."""
    vault = _get_vault(vault_path, passphrase)
    try:
        result = check_expiry(vault, environment, key)
    except ExpiryError as exc:
        raise click.ClickException(str(exc)) from exc

    if result.expires_at is None:
        click.echo(f"{key}: no expiry set")
    elif result.is_expired:
        click.echo(f"{key}: EXPIRED (was {result.expires_at})", err=False)
    else:
        click.echo(f"{key}: expires {result.expires_at} ({result.days_remaining} days remaining)")


@expiry_group.command("list")
@click.option("--vault", "vault_path", required=True, envvar="ENVAULT_VAULT", help="Path to vault file.")
@click.option("--passphrase", required=True, envvar="ENVAULT_PASSPHRASE", hide_input=True, help="Vault passphrase.")
@click.option("--env", "environment", required=True, help="Target environment.")
@click.option("--within", "within_days", type=int, default=30, show_default=True, help="Days window.")
def list_cmd(vault_path, passphrase, environment, within_days):
    """List secrets expiring within a number of days."""
    vault = _get_vault(vault_path, passphrase)
    results = list_expiring(vault, environment, within_days=within_days)
    if not results:
        click.echo("No secrets expiring soon.")
        return
    for r in results:
        status = "EXPIRED" if r.is_expired else f"{r.days_remaining}d remaining"
        click.echo(f"{r.key}: {r.expires_at} [{status}]")
