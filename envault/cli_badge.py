"""CLI commands for badge generation."""
import json

import click

from envault.badge import BadgeError, generate_all_badges, generate_badge
from envault.cli import _get_vault


@click.group("badge")
def badge_group() -> None:
    """Generate shields.io status badges for secrets."""


@badge_group.command("generate")
@click.argument("environment")
@click.option("--style", default="flat", show_default=True, help="Badge style.")
@click.option("--label", default=None, help="Custom label text.")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
def generate_cmd(
    environment: str,
    style: str,
    label,
    as_json: bool,
    vault_file: str,
    passphrase: str,
) -> None:
    """Generate a badge for a single ENVIRONMENT."""
    vault = _get_vault(vault_file, passphrase)
    try:
        result = generate_badge(vault, environment, style=style, label=label)
    except BadgeError as exc:
        raise click.ClickException(str(exc))

    if as_json:
        click.echo(json.dumps(result.to_dict(), indent=2))
    else:
        click.echo(f"Label  : {result.label}")
        click.echo(f"Message: {result.message}")
        click.echo(f"Color  : {result.color}")
        click.echo(f"URL    : {result.url}")


@badge_group.command("all")
@click.option("--style", default="flat", show_default=True, help="Badge style.")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
def all_cmd(style: str, as_json: bool, vault_file: str, passphrase: str) -> None:
    """Generate badges for all environments."""
    vault = _get_vault(vault_file, passphrase)
    try:
        results = generate_all_badges(vault, style=style)
    except BadgeError as exc:
        raise click.ClickException(str(exc))

    if as_json:
        click.echo(json.dumps({k: v.to_dict() for k, v in results.items()}, indent=2))
    else:
        if not results:
            click.echo("No environments found.")
            return
        for env, result in results.items():
            click.echo(f"[{env}] {result.message}  →  {result.url}")
