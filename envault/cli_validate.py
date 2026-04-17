"""CLI commands for secret validation."""
import click
import json
from envault.cli import _get_vault
from envault.validate import validate_secrets, ValidateError, VALIDATE_RULES


@click.group("validate")
def validate_group():
    """Validate secret values against rules."""


@validate_group.command("run")
@click.argument("environment")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", envvar="ENVAULT_PASSPHRASE", prompt=True, hide_input=True)
@click.option("--min-length", type=int, default=None)
@click.option("--max-length", type=int, default=None)
@click.option("--regex", default=None, help="Require values to match this pattern.")
@click.option("--no-spaces", is_flag=True, default=False)
@click.option("--allow-empty", is_flag=True, default=False)
@click.option("--output", type=click.Choice(["text", "json"]), default="text")
def run_cmd(environment, vault_file, passphrase, min_length, max_length,
            regex, no_spaces, allow_empty, output):
    """Run validation rules against secrets in ENVIRONMENT."""
    vault = _get_vault(vault_file, passphrase)
    try:
        result = validate_secrets(
            vault, environment,
            min_length=min_length,
            max_length=max_length,
            regex=regex,
            no_spaces=no_spaces,
            not_empty=not allow_empty,
        )
    except ValidateError as exc:
        raise click.ClickException(str(exc))

    if output == "json":
        click.echo(json.dumps(result.to_dict(), indent=2))
    else:
        if result.passed:
            click.echo("All secrets passed validation.")
        else:
            for issue in result.issues:
                click.echo(f"[{issue.rule}] {issue.message}")
            raise click.ClickException(f"{len(result.issues)} validation issue(s) found.")


@validate_group.command("rules")
def rules_cmd():
    """List available validation rules."""
    for rule in VALIDATE_RULES:
        click.echo(rule)
