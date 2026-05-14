"""CLI commands for expiry warning checks."""
from __future__ import annotations

import json

import click

from envault.cli import _get_vault
from envault.expire_warn import ExpireWarnError, check_expiry_warning, check_all_expiry_warnings


@click.group("expire-warn")
def expire_warn_group() -> None:
    """Check secrets approaching or past expiry."""


@expire_warn_group.command("check")
@click.argument("environment")
@click.argument("key")
@click.option("--threshold", default=7, show_default=True, help="Warning threshold in days.")
@click.option("--vault-file", default="vault.enc", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
@click.option("--json", "as_json", is_flag=True, default=False)
def check_cmd(environment: str, key: str, threshold: int, vault_file: str, passphrase: str, as_json: bool) -> None:
    """Check a single secret for expiry warning."""
    try:
        vault = _get_vault(vault_file, passphrase)
        result = check_expiry_warning(vault, environment, key, threshold)
    except ExpireWarnError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)

    if as_json:
        click.echo(json.dumps(result.to_dict(), indent=2))
    elif result.is_expired:
        click.echo(f"[EXPIRED] '{key}' expired {abs(result.days_remaining)} day(s) ago ({result.expires_at}).")
    elif result.warning:
        click.echo(f"[WARNING] '{key}' expires in {result.days_remaining} day(s) ({result.expires_at}).")
    else:
        msg = f"[OK] '{key}' is not near expiry."
        if result.expires_at:
            msg += f" Expires in {result.days_remaining} day(s)."
        click.echo(msg)


@expire_warn_group.command("scan")
@click.argument("environment")
@click.option("--threshold", default=7, show_default=True, help="Warning threshold in days.")
@click.option("--vault-file", default="vault.enc", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
@click.option("--json", "as_json", is_flag=True, default=False)
def scan_cmd(environment: str, threshold: int, vault_file: str, passphrase: str, as_json: bool) -> None:
    """Scan all secrets in an environment for expiry warnings."""
    vault = _get_vault(vault_file, passphrase)
    results = check_all_expiry_warnings(vault, environment, threshold)

    if as_json:
        click.echo(json.dumps([r.to_dict() for r in results], indent=2))
        return

    if not results:
        click.echo("All secrets are healthy (no expiry warnings).")
        return

    for r in results:
        tag = "EXPIRED" if r.is_expired else "WARNING"
        click.echo(f"[{tag}] {r.key}: {r.expires_at} ({r.days_remaining} day(s) remaining)")
