"""CLI commands for secret value history."""
import click

from envault.cli import _get_vault, _get_audit
from envault.history import HistoryError, get_history, record_history


@click.group("history")
def history_group():
    """View and manage secret value history."""


@history_group.command("record")
@click.argument("environment")
@click.argument("key")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
@click.option("--by", default="cli", show_default=True, help="Actor recording the snapshot.")
def record_cmd(environment: str, key: str, vault_file: str, passphrase: str, by: str):
    """Snapshot the current value of KEY into history."""
    vault = _get_vault(vault_file, passphrase)
    try:
        entry = record_history(vault, environment, key, updated_by=by)
    except HistoryError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Recorded version {entry.version} of '{key}' in '{environment}' at {entry.updated_at}.")


@history_group.command("list")
@click.argument("environment")
@click.argument("key")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
@click.option("--limit", default=10, show_default=True, help="Maximum number of entries to show.")
def list_cmd(environment: str, key: str, vault_file: str, passphrase: str, limit: int):
    """List historical versions of KEY in ENVIRONMENT."""
    vault = _get_vault(vault_file, passphrase)
    entries = get_history(vault, environment, key, limit=limit)
    if not entries:
        click.echo(f"No history found for '{key}' in '{environment}'.")
        return
    click.echo(f"History for '{key}' in '{environment}' (newest first):")
    for e in entries:
        click.echo(f"  v{e.version}  {e.updated_at}  by={e.updated_by}")
