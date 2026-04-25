"""CLI commands for quota management."""
import click

from envault.cli import _get_vault
from envault.quota import QuotaError, check_quota, set_quota


@click.group("quota", help="Manage per-environment secret quotas.")
def quota_group() -> None:
    pass


@quota_group.command("set")
@click.argument("environment")
@click.argument("limit", type=int)
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
def set_cmd(environment: str, limit: int, vault_file: str, passphrase: str) -> None:
    """Set the maximum number of secrets for ENVIRONMENT."""
    vault = _get_vault(vault_file, passphrase)
    try:
        result = set_quota(vault, environment, limit)
    except QuotaError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(
        f"Quota for '{result.environment}' set to {result.limit} "
        f"(used: {result.used}, remaining: {result.remaining})."
    )


@quota_group.command("check")
@click.argument("environment")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
@click.option("--json", "as_json", is_flag=True, default=False, help="Output as JSON.")
def check_cmd(environment: str, vault_file: str, passphrase: str, as_json: bool) -> None:
    """Show quota status for ENVIRONMENT."""
    import json as _json

    vault = _get_vault(vault_file, passphrase)
    result = check_quota(vault, environment)
    if as_json:
        click.echo(_json.dumps(result.to_dict(), indent=2))
        return
    status = "EXCEEDED" if result.exceeded else "OK"
    click.echo(
        f"[{status}] {result.environment}: "
        f"{result.used}/{result.limit} secrets used, "
        f"{result.remaining} remaining."
    )
    if result.exceeded:
        raise SystemExit(1)
