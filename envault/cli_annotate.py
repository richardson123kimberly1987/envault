"""CLI commands for managing secret annotations."""
from __future__ import annotations

import click

from envault.annotate import AnnotateError, set_annotation, remove_annotation, get_annotation
from envault.cli import _get_vault


@click.group("annotate", help="Manage annotations on secrets.")
def annotate_group() -> None:
    pass


@annotate_group.command("set")
@click.argument("environment")
@click.argument("secret")
@click.argument("text")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
def set_cmd(environment: str, secret: str, text: str, vault_file: str, passphrase: str) -> None:
    """Set or replace the annotation on SECRET in ENVIRONMENT."""
    try:
        vault = _get_vault(vault_file, passphrase)
        result = set_annotation(vault, environment, secret, text)
        if result.previous:
            click.echo(f"Updated annotation on '{secret}' (was: {result.previous!r}).")
        else:
            click.echo(f"Annotation set on '{secret}'.")
    except AnnotateError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)


@annotate_group.command("remove")
@click.argument("environment")
@click.argument("secret")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
def remove_cmd(environment: str, secret: str, vault_file: str, passphrase: str) -> None:
    """Remove the annotation from SECRET in ENVIRONMENT."""
    try:
        vault = _get_vault(vault_file, passphrase)
        result = remove_annotation(vault, environment, secret)
        if result.previous:
            click.echo(f"Annotation removed from '{secret}' (was: {result.previous!r}).")
        else:
            click.echo(f"No annotation was set on '{secret}'.")
    except AnnotateError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)


@annotate_group.command("get")
@click.argument("environment")
@click.argument("secret")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
def get_cmd(environment: str, secret: str, vault_file: str, passphrase: str) -> None:
    """Print the annotation for SECRET in ENVIRONMENT."""
    try:
        vault = _get_vault(vault_file, passphrase)
        annotation = get_annotation(vault, environment, secret)
        if annotation:
            click.echo(annotation)
        else:
            click.echo(f"No annotation set on '{secret}'.")
    except AnnotateError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)
