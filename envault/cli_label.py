"""CLI commands for secret label management."""
from __future__ import annotations

import json

import click

from envault.label import LabelError, set_label, remove_label, list_labels


@click.group("label")
def label_group() -> None:
    """Attach and manage key/value labels on secrets."""


@label_group.command("set")
@click.argument("environment")
@click.argument("secret")
@click.argument("key")
@click.argument("value")
@click.option("--vault-file", default="vault.json", show_default=True, help="Path to vault file.")
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
def set_cmd(environment: str, secret: str, key: str, value: str, vault_file: str, passphrase: str) -> None:
    """Set a label KEY=VALUE on SECRET in ENVIRONMENT."""
    from envault.cli import _get_vault

    vault = _get_vault(vault_file, passphrase)
    try:
        result = set_label(vault, environment, secret, key, value)
        vault.save()
    except LabelError as exc:
        raise click.ClickException(str(exc)) from exc

    status = "updated" if not result.changed else "set"
    click.echo(f"Label {key!r} {status} on {secret!r} [{environment}]")


@label_group.command("remove")
@click.argument("environment")
@click.argument("secret")
@click.argument("key")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
def remove_cmd(environment: str, secret: str, key: str, vault_file: str, passphrase: str) -> None:
    """Remove label KEY from SECRET in ENVIRONMENT."""
    from envault.cli import _get_vault

    vault = _get_vault(vault_file, passphrase)
    try:
        remove_label(vault, environment, secret, key)
        vault.save()
    except LabelError as exc:
        raise click.ClickException(str(exc)) from exc

    click.echo(f"Label {key!r} removed from {secret!r} [{environment}]")


@label_group.command("list")
@click.argument("environment")
@click.argument("secret")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
@click.option("--json", "as_json", is_flag=True, default=False, help="Output as JSON.")
def list_cmd(environment: str, secret: str, vault_file: str, passphrase: str, as_json: bool) -> None:
    """List all labels on SECRET in ENVIRONMENT."""
    from envault.cli import _get_vault

    vault = _get_vault(vault_file, passphrase)
    try:
        result = list_labels(vault, environment, secret)
    except LabelError as exc:
        raise click.ClickException(str(exc)) from exc

    if as_json:
        click.echo(json.dumps(result.to_dict(), indent=2))
        return

    if not result.labels:
        click.echo(f"No labels on {secret!r} [{environment}]")
        return

    click.echo(f"Labels for {secret!r} [{environment}]:")
    for k, v in sorted(result.labels.items()):
        click.echo(f"  {k} = {v}")
