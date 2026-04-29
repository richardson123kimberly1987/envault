"""CLI commands for secret categorization."""
import click

from envault.categorize import CATEGORIES, CategorizeError, list_by_category, set_category
from envault.cli import _get_vault


@click.group("categorize")
def categorize_group():
    """Manage secret categories."""


@categorize_group.command("set")
@click.argument("environment")
@click.argument("secret")
@click.argument("category", type=click.Choice(CATEGORIES))
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
def set_cmd(environment, secret, category, vault_file, passphrase):
    """Set the category for a secret."""
    vault = _get_vault(vault_file, passphrase)
    try:
        result = set_category(vault, environment, secret, category)
        vault.save()
        prev = result.previous or "(none)"
        click.echo(
            f"Set category of '{secret}' in '{environment}' to '{category}' (was {prev})."
        )
    except CategorizeError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)


@categorize_group.command("list")
@click.argument("environment")
@click.option("--category", type=click.Choice(CATEGORIES), default=None)
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
def list_cmd(environment, category, vault_file, passphrase):
    """List secrets and their categories."""
    vault = _get_vault(vault_file, passphrase)
    try:
        items = list_by_category(vault, environment, category)
        if not items:
            click.echo("No secrets found.")
            return
        for item in items:
            click.echo(f"{item['secret']}: {item['category']}")
    except CategorizeError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)
