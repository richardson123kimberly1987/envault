"""CLI commands for promoting secrets between environments."""
import click
from envault.cli import _get_vault
from envault.promote import promote_environment, PromoteError


@click.group("promote")
def promote_group():
    """Promote secrets from one environment to another."""


@promote_group.command("run")
@click.argument("source")
@click.argument("destination")
@click.option("--key", "keys", multiple=True, help="Specific keys to promote (default: all).")
@click.option("--overwrite", is_flag=True, default=False, help="Overwrite existing keys in destination.")
@click.option("--dry-run", is_flag=True, default=False, help="Preview changes without applying them.")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
def run_cmd(source, destination, keys, overwrite, dry_run, vault_file, passphrase):
    """Promote secrets from SOURCE to DESTINATION environment."""
    vault = _get_vault(vault_file, passphrase)
    try:
        result = promote_environment(
            vault,
            source=source,
            destination=destination,
            keys=list(keys) if keys else None,
            overwrite=overwrite,
            dry_run=dry_run,
        )
    except PromoteError as exc:
        raise click.ClickException(str(exc))

    prefix = "[dry-run] " if dry_run else ""
    if result.promoted:
        click.echo(f"{prefix}Promoted: {', '.join(result.promoted)}")
    if result.overwritten:
        click.echo(f"{prefix}Overwritten: {', '.join(result.overwritten)}")
    if result.skipped:
        click.echo(f"Skipped (already exist): {', '.join(result.skipped)}")
    if not dry_run and (result.promoted or result.overwritten):
        vault.save()
        click.echo(f"Vault saved.")
    if not result.promoted and not result.overwritten:
        click.echo("Nothing to promote.")
