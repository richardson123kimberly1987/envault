"""CLI commands for secret scope management."""
import click

from envault.cli import _get_vault
from envault.scope import ScopeError, add_scope, remove_scope, list_scopes, filter_by_scope


@click.group("scope")
def scope_group():
    """Manage scopes assigned to secrets."""


@scope_group.command("add")
@click.argument("environment")
@click.argument("secret")
@click.argument("scope")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
def add_cmd(environment, secret, scope, vault_file, passphrase):
    """Add SCOPE to SECRET in ENVIRONMENT."""
    try:
        vault = _get_vault(vault_file, passphrase)
        result = add_scope(vault, environment, secret, scope)
        click.echo(f"Scope '{scope}' added to '{secret}'. Current scopes: {result.scopes}")
    except ScopeError as exc:
        raise click.ClickException(str(exc)) from exc


@scope_group.command("remove")
@click.argument("environment")
@click.argument("secret")
@click.argument("scope")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
def remove_cmd(environment, secret, scope, vault_file, passphrase):
    """Remove SCOPE from SECRET in ENVIRONMENT."""
    try:
        vault = _get_vault(vault_file, passphrase)
        result = remove_scope(vault, environment, secret, scope)
        click.echo(f"Scope '{scope}' removed from '{secret}'. Remaining scopes: {result.scopes}")
    except ScopeError as exc:
        raise click.ClickException(str(exc)) from exc


@scope_group.command("list")
@click.argument("environment")
@click.argument("secret")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
def list_cmd(environment, secret, vault_file, passphrase):
    """List scopes assigned to SECRET in ENVIRONMENT."""
    try:
        vault = _get_vault(vault_file, passphrase)
        result = list_scopes(vault, environment, secret)
        if result.scopes:
            click.echo("\n".join(result.scopes))
        else:
            click.echo("No scopes assigned.")
    except ScopeError as exc:
        raise click.ClickException(str(exc)) from exc


@scope_group.command("filter")
@click.argument("environment")
@click.argument("scope")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
def filter_cmd(environment, scope, vault_file, passphrase):
    """List secrets in ENVIRONMENT that carry SCOPE."""
    try:
        vault = _get_vault(vault_file, passphrase)
        names = filter_by_scope(vault, environment, scope)
        if names:
            click.echo("\n".join(names))
        else:
            click.echo(f"No secrets found with scope '{scope}'.")
    except ScopeError as exc:
        raise click.ClickException(str(exc)) from exc
