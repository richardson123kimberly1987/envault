"""CLI commands for namespace management."""
import click

from envault.cli import _get_vault
from envault.namespace import (
    NamespaceError,
    list_in_namespace,
    move_to_namespace,
    remove_from_namespace,
)


@click.group("namespace")
def namespace_group() -> None:
    """Manage secret namespaces."""


@namespace_group.command("list")
@click.argument("namespace")
@click.option("--env", default="default", show_default=True, help="Target environment.")
@click.option("--vault-file", default="vault.enc", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
def list_cmd(namespace: str, env: str, vault_file: str, passphrase: str) -> None:
    """List secrets inside NAMESPACE."""
    try:
        vault = _get_vault(vault_file, passphrase)
        result = list_in_namespace(vault, env, namespace)
        if result.secrets:
            for key in result.secrets:
                click.echo(key)
        else:
            click.echo(f"No secrets found in namespace '{namespace}'.")
    except NamespaceError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)


@namespace_group.command("move")
@click.argument("key")
@click.argument("namespace")
@click.option("--env", default="default", show_default=True, help="Target environment.")
@click.option("--overwrite", is_flag=True, default=False, help="Overwrite if destination exists.")
@click.option("--vault-file", default="vault.enc", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
def move_cmd(key: str, namespace: str, env: str, overwrite: bool, vault_file: str, passphrase: str) -> None:
    """Move KEY into NAMESPACE (renames to NAMESPACE/KEY)."""
    try:
        vault = _get_vault(vault_file, passphrase)
        result = move_to_namespace(vault, env, key, namespace, overwrite=overwrite)
        click.echo(f"Moved '{key}' -> '{result.secrets[0]}'")
    except NamespaceError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)


@namespace_group.command("remove")
@click.argument("key")
@click.option("--namespace", default=None, help="Expected namespace (optional validation).")
@click.option("--env", default="default", show_default=True, help="Target environment.")
@click.option("--vault-file", default="vault.enc", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
def remove_cmd(key: str, namespace: str, env: str, vault_file: str, passphrase: str) -> None:
    """Strip the namespace prefix from KEY, moving it to the root."""
    try:
        vault = _get_vault(vault_file, passphrase)
        result = remove_from_namespace(vault, env, key, namespace=namespace)
        click.echo(f"Moved '{key}' -> '{result.secrets[0]}'")
    except NamespaceError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)
