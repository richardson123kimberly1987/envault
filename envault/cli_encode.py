"""CLI commands for encoding/decoding secret values."""

from __future__ import annotations

import click

from envault.cli import _get_vault
from envault.encode import ENCODE_FORMATS, EncodeError, decode_secret, encode_secret


@click.group("encode")
def encode_group() -> None:
    """Encode or decode secret values."""


@encode_group.command("run")
@click.argument("environment")
@click.argument("secret")
@click.option("--format", "fmt", default="base64", show_default=True,
              type=click.Choice(ENCODE_FORMATS), help="Encoding format.")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True,
              hide_input=True)
def encode_cmd(environment: str, secret: str, fmt: str, vault_file: str,
               passphrase: str) -> None:
    """Encode a secret value."""
    vault = _get_vault(vault_file)
    try:
        result = encode_secret(vault, environment, secret, fmt, passphrase)
    except EncodeError as exc:
        raise click.ClickException(str(exc))
    click.echo(result.encoded)


@encode_group.command("decode")
@click.argument("environment")
@click.argument("secret")
@click.option("--format", "fmt", default="base64", show_default=True,
              type=click.Choice(ENCODE_FORMATS), help="Encoding format.")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True,
              hide_input=True)
def decode_cmd(environment: str, secret: str, fmt: str, vault_file: str,
               passphrase: str) -> None:
    """Decode a secret value."""
    vault = _get_vault(vault_file)
    try:
        result = decode_secret(vault, environment, secret, fmt, passphrase)
    except EncodeError as exc:
        raise click.ClickException(str(exc))
    click.echo(result.encoded)
