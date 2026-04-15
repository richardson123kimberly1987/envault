"""CLI entry-point for envault."""

from __future__ import annotations

import json
import os
import sys

import click

from envault.audit import AuditLog
from envault.search import SearchError, search_secrets
from envault.vault import Vault, VaultError

_DEFAULT_VAULT = os.environ.get("ENVAULT_VAULT", "vault.enc")
_DEFAULT_AUDIT = os.environ.get("ENVAULT_AUDIT", "audit.log")


def _get_vault(path: str, passphrase: str) -> Vault:
    return Vault(path, passphrase)


def _get_audit(path: str) -> AuditLog:
    return AuditLog(path)


@click.group()
def cli() -> None:
    """envault — secure environment secret manager."""


@cli.command("set")
@click.argument("environment")
@click.argument("key")
@click.argument("value")
@click.option("--vault", default=_DEFAULT_VAULT, show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
@click.option("--audit", default=_DEFAULT_AUDIT, show_default=True)
def set_secret(environment, key, value, vault, passphrase, audit):
    """Set a secret KEY=VALUE in ENVIRONMENT."""
    try:
        v = _get_vault(vault, passphrase)
        v.set(environment, key, value)
        v.save()
        _get_audit(audit).record("set", environment=environment, key=key)
        click.echo(f"Set {key} in {environment}.")
    except VaultError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


@cli.command("get")
@click.argument("environment")
@click.argument("key")
@click.option("--vault", default=_DEFAULT_VAULT, show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
def get_secret(environment, key, vault, passphrase):
    """Get a secret KEY from ENVIRONMENT."""
    try:
        v = _get_vault(vault, passphrase)
        value = v.get(environment, key)
        if value is None:
            click.echo(f"Key '{key}' not found in {environment}.", err=True)
            sys.exit(1)
        click.echo(value)
    except VaultError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


@cli.command("list")
@click.argument("environment")
@click.option("--vault", default=_DEFAULT_VAULT, show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
def list_secrets(environment, vault, passphrase):
    """List all secret keys in ENVIRONMENT."""
    try:
        v = _get_vault(vault, passphrase)
        keys = v.list_secrets(environment)
        for k in sorted(keys):
            click.echo(k)
    except VaultError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


@cli.command("search")
@click.argument("pattern")
@click.option("--environment", default=None, help="Restrict to a single environment.")
@click.option("--regex", "use_regex", is_flag=True, default=False, help="Treat PATTERN as regex.")
@click.option("--vault", default=_DEFAULT_VAULT, show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
@click.option("--json", "as_json", is_flag=True, default=False, help="Output as JSON.")
def search(pattern, environment, use_regex, vault, passphrase, as_json):
    """Search for secrets matching PATTERN (glob by default)."""
    try:
        v = _get_vault(vault, passphrase)
        results = search_secrets(v, pattern, environment=environment, use_regex=use_regex)
        if not results:
            click.echo("No secrets matched.")
            return
        if as_json:
            click.echo(json.dumps([r.to_dict() for r in results], indent=2))
        else:
            for r in results:
                click.echo(f"{r.environment}\t{r.key}\tv{r.version}")
    except SearchError as exc:
        click.echo(f"Search error: {exc}", err=True)
        sys.exit(1)
    except VaultError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
