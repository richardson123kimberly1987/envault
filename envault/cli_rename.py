"""CLI commands for renaming secrets."""
from __future__ import annotations

import click

from envault.cli import _get_vault, _get_audit
from envault.rename import rename_secret, RenameError


@click.group("rename")
def rename_group() -> None:
    """Rename secrets within the vault."""


@rename_group.command("secret")
@click.argument("old_name")
@click.argument("new_name")
@click.option("--vault-file", default="vault.json", show_default=True, help="Path to vault file.")
@click.option("--passphrase", prompt=True, hide_input=True, help="Vault passphrase.")
@click.option("--env", default=None, help="Limit rename to a specific environment.")
@click.option("--audit-file", default="audit.log", show_default=True, help="Path to audit log.")
def secret_cmd(
    old_name: str,
    new_name: str,
    vault_file: str,
    passphrase: str,
    env: str | None,
    audit_file: str,
) -> None:
    """Rename OLD_NAME to NEW_NAME across all (or a specific) environment."""
    try:
        vault = _get_vault(vault_file, passphrase)
        result = rename_secret(vault, old_name, new_name, env=env)
        vault.save()

        audit = _get_audit(audit_file)
        audit.record(
            "rename_secret",
            {
                "old_name": old_name,
                "new_name": new_name,
                "environments_updated": result.environments_updated,
            },
        )

        click.echo(
            f"Renamed '{old_name}' -> '{new_name}' "
            f"in {len(result.environments_updated)} environment(s): "
            f"{', '.join(result.environments_updated)}"
        )
        if result.skipped_environments:
            click.echo(
                f"Skipped (key absent): {', '.join(result.skipped_environments)}"
            )
    except RenameError as exc:
        raise click.ClickException(str(exc)) from exc
