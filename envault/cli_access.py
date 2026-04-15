"""CLI commands for managing access control policies in envault."""

from __future__ import annotations

import json
from pathlib import Path

import click

from envault.access import ACCESS_ROLES, AccessError, AccessPolicy

_POLICY_FILE = Path(".envault_access.json")


def _load_policy() -> AccessPolicy:
    if _POLICY_FILE.exists():
        data = json.loads(_POLICY_FILE.read_text())
        return AccessPolicy.from_dict(data)
    return AccessPolicy()


def _save_policy(policy: AccessPolicy) -> None:
    _POLICY_FILE.write_text(json.dumps(policy.to_dict(), indent=2))


@click.group(name="access")
def access_group() -> None:
    """Manage role-based access control for secrets."""


@access_group.command(name="grant")
@click.argument("identity")
@click.argument("role", type=click.Choice(ACCESS_ROLES))
@click.option("--env", "environment", default=None, help="Limit to a specific environment.")
def grant_cmd(identity: str, role: str, environment: str | None) -> None:
    """Grant IDENTITY the ROLE, optionally scoped to --env."""
    try:
        policy = _load_policy()
        policy.add_rule(identity, role, environment)
        _save_policy(policy)
        scope = f" in '{environment}'" if environment else " globally"
        click.echo(f"Granted '{role}' to '{identity}'{scope}.")
    except AccessError as exc:
        raise click.ClickException(str(exc)) from exc


@access_group.command(name="revoke")
@click.argument("identity")
@click.option("--env", "environment", default=None, help="Revoke only for a specific environment.")
def revoke_cmd(identity: str, environment: str | None) -> None:
    """Revoke access for IDENTITY, optionally scoped to --env."""
    policy = _load_policy()
    removed = policy.remove_rule(identity, environment)
    if removed:
        _save_policy(policy)
        scope = f" in '{environment}'" if environment else " globally"
        click.echo(f"Revoked access for '{identity}'{scope}.")
    else:
        click.echo(f"No matching rule found for '{identity}'.")


@access_group.command(name="list")
@click.option("--env", "environment", default=None, help="Filter rules by environment.")
def list_cmd(environment: str | None) -> None:
    """List all access rules, optionally filtered by --env."""
    policy = _load_policy()
    rules = [
        r for r in policy.rules
        if environment is None or r.environment == environment or r.environment is None
    ]
    if not rules:
        click.echo("No access rules defined.")
        return
    for rule in rules:
        scope = rule.environment or "*"
        click.echo(f"{rule.identity:20s}  {rule.role:8s}  env={scope}")


@access_group.command(name="check")
@click.argument("identity")
@click.argument("action", type=click.Choice(ACCESS_ROLES))
@click.option("--env", "environment", default=None)
def check_cmd(identity: str, action: str, environment: str | None) -> None:
    """Check whether IDENTITY can perform ACTION."""
    try:
        policy = _load_policy()
        allowed = policy.can(identity, action, environment)
        status = "ALLOWED" if allowed else "DENIED"
        click.echo(f"{status}: '{identity}' -> '{action}' (env={environment or '*'})")
    except AccessError as exc:
        raise click.ClickException(str(exc)) from exc
