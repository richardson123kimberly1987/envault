"""CLI commands for inspecting available cipher suites."""
from __future__ import annotations

import json

import click

from envault.cipher import CipherError, get_cipher_info, list_ciphers


@click.group("cipher", help="Inspect available cipher suites.")
def cipher_group() -> None:
    pass


@cipher_group.command("list")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def list_cmd(as_json: bool) -> None:
    """List all supported cipher suites."""
    ciphers = list_ciphers()
    if as_json:
        click.echo(json.dumps([c.to_dict() for c in ciphers], indent=2))
        return
    for info in ciphers:
        default_marker = " (default)" if info.is_default else ""
        click.echo(
            f"{info.name}{default_marker}\n"
            f"  key_bits    : {info.key_bits}\n"
            f"  mode        : {info.mode}\n"
            f"  authenticated: {info.authenticated}\n"
            f"  {info.description}\n"
        )


@cipher_group.command("info")
@click.argument("name")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def info_cmd(name: str, as_json: bool) -> None:
    """Show details for a specific cipher suite NAME."""
    try:
        info = get_cipher_info(name)
    except CipherError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)

    if as_json:
        click.echo(json.dumps(info.to_dict(), indent=2))
        return

    default_marker = " (default)" if info.is_default else ""
    click.echo(
        f"Cipher : {info.name}{default_marker}\n"
        f"Key bits: {info.key_bits}\n"
        f"Mode    : {info.mode}\n"
        f"Auth    : {info.authenticated}\n"
        f"Info    : {info.description}"
    )
