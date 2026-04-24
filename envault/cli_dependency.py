"""CLI commands for secret dependency management."""
import click

from envault.cli import _get_vault
from envault.dependency import (
    DependencyError,
    add_dependency,
    list_dependencies,
    remove_dependency,
    resolve_order,
)


@click.group("dependency")
def dependency_group() -> None:
    """Manage inter-secret dependencies."""


@dependency_group.command("add")
@click.argument("secret")
@click.argument("depends_on")
@click.option("--env", default="default", show_default=True, help="Environment name")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
def add_cmd(secret: str, depends_on: str, env: str, vault_file: str, passphrase: str) -> None:
    """Record that SECRET depends on DEPENDS_ON."""
    try:
        vault = _get_vault(vault_file, passphrase)
        result = add_dependency(vault, secret, env, depends_on)
        vault.save()
        click.echo(f"Added dependency: {secret} -> {depends_on} (deps: {result.depends_on})")
    except DependencyError as exc:
        raise click.ClickException(str(exc)) from exc


@dependency_group.command("remove")
@click.argument("secret")
@click.argument("depends_on")
@click.option("--env", default="default", show_default=True)
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
def remove_cmd(secret: str, depends_on: str, env: str, vault_file: str, passphrase: str) -> None:
    """Remove a dependency from SECRET."""
    try:
        vault = _get_vault(vault_file, passphrase)
        result = remove_dependency(vault, secret, env, depends_on)
        vault.save()
        click.echo(f"Removed dependency: {secret} -> {depends_on} (remaining: {result.depends_on})")
    except DependencyError as exc:
        raise click.ClickException(str(exc)) from exc


@dependency_group.command("list")
@click.argument("secret")
@click.option("--env", default="default", show_default=True)
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
def list_cmd(secret: str, env: str, vault_file: str, passphrase: str) -> None:
    """List dependencies for SECRET."""
    vault = _get_vault(vault_file, passphrase)
    result = list_dependencies(vault, secret, env)
    if result.depends_on:
        for dep in result.depends_on:
            click.echo(dep)
    else:
        click.echo("No dependencies recorded.")


@dependency_group.command("resolve")
@click.option("--env", default="default", show_default=True)
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
def resolve_cmd(env: str, vault_file: str, passphrase: str) -> None:
    """Print secrets in dependency-resolved order for ENV."""
    try:
        vault = _get_vault(vault_file, passphrase)
        order = resolve_order(vault, env)
        for name in order:
            click.echo(name)
    except DependencyError as exc:
        raise click.ClickException(str(exc)) from exc
