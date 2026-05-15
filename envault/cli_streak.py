"""CLI commands for rotation streak tracking."""
from __future__ import annotations

import json
import sys

import click

from envault.cli import _get_vault
from envault.streak import StreakError, get_streak, record_rotation, reset_streak


@click.group("streak")
def streak_group() -> None:
    """Track consecutive on-time rotation streaks."""


@streak_group.command("record")
@click.argument("environment")
@click.argument("secret")
@click.option("--vault", "vault_path", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
@click.option("--json", "as_json", is_flag=True, default=False)
def record_cmd(
    environment: str,
    secret: str,
    vault_path: str,
    passphrase: str,
    as_json: bool,
) -> None:
    """Record a successful rotation for SECRET in ENVIRONMENT."""
    try:
        vault = _get_vault(vault_path, passphrase)
        result = record_rotation(vault, environment, secret)
    except StreakError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    if as_json:
        click.echo(json.dumps(result.to_dict(), indent=2))
    else:
        click.echo(
            f"Streak recorded for '{secret}' [{environment}]: "
            f"{result.current_streak} consecutive rotation(s) "
            f"(best: {result.longest_streak})"
        )


@streak_group.command("get")
@click.argument("environment")
@click.argument("secret")
@click.option("--vault", "vault_path", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
@click.option("--json", "as_json", is_flag=True, default=False)
def get_cmd(
    environment: str,
    secret: str,
    vault_path: str,
    passphrase: str,
    as_json: bool,
) -> None:
    """Show the rotation streak for SECRET in ENVIRONMENT."""
    try:
        vault = _get_vault(vault_path, passphrase)
        result = get_streak(vault, environment, secret)
    except StreakError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    if as_json:
        click.echo(json.dumps(result.to_dict(), indent=2))
    else:
        click.echo(
            f"'{secret}' [{environment}]: current={result.current_streak}, "
            f"best={result.longest_streak}, last={result.last_rotated or 'never'}"
        )


@streak_group.command("reset")
@click.argument("environment")
@click.argument("secret")
@click.option("--vault", "vault_path", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
def reset_cmd(
    environment: str,
    secret: str,
    vault_path: str,
    passphrase: str,
) -> None:
    """Reset the rotation streak for SECRET in ENVIRONMENT."""
    try:
        vault = _get_vault(vault_path, passphrase)
        reset_streak(vault, environment, secret)
    except StreakError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
    click.echo(f"Streak reset for '{secret}' [{environment}].")
