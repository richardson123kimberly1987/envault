import click
from envault.cli import _get_vault
from envault.merge import merge_environments, MergeError


@click.group("merge")
def merge_group():
    """Merge secrets between environments."""


@merge_group.command("envs")
@click.argument("source")
@click.argument("target")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
@click.option(
    "--strategy",
    type=click.Choice(["keep", "overwrite", "skip"]),
    default="keep",
    show_default=True,
    help="Conflict resolution strategy.",
)
@click.option("--dry-run", is_flag=True, default=False, help="Preview without saving.")
def envs_cmd(source, target, vault_file, passphrase, strategy, dry_run):
    """Merge secrets from SOURCE environment into TARGET environment."""
    vault = _get_vault(vault_file, passphrase)
    try:
        result = merge_environments(vault, source, target, strategy=strategy)
    except MergeError as exc:
        raise click.ClickException(str(exc))

    for key, status in result.details.items():
        click.echo(f"  {key}: {status}")

    click.echo(
        f"\nMerged {result.merged} secret(s) into '{target}' "
        f"({result.skipped} skipped, {result.conflicts} conflict(s) resolved with '{strategy}')."
    )

    if not dry_run:
        vault.save()
        click.echo("Vault saved.")
    else:
        click.echo("[dry-run] No changes written.")
