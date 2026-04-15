"""CLI commands for linting vault secrets."""
import json
import click
from envault.cli import _get_vault
from envault.lint import lint_secrets, LintError


@click.group("lint")
def lint_group():
    """Lint secrets for common issues."""


@lint_group.command("run")
@click.option("--vault-file", default="vault.json", show_default=True, help="Path to vault file.")
@click.option("--passphrase", prompt=True, hide_input=True, help="Vault passphrase.")
@click.option("--env", default=None, help="Limit lint to a specific environment.")
@click.option("--format", "output_format", default="text", type=click.Choice(["text", "json"]), show_default=True)
@click.option("--fail-on-issues", is_flag=True, default=False, help="Exit with code 1 if issues found.")
def run_cmd(vault_file, passphrase, env, output_format, fail_on_issues):
    """Run all lint checks against vault secrets."""
    try:
        vault = _get_vault(vault_file, passphrase)
        result = lint_secrets(vault, environment=env)
    except LintError as exc:
        raise click.ClickException(str(exc))

    if output_format == "json":
        click.echo(json.dumps(result.to_dict(), indent=2))
    else:
        if result.passed:
            click.secho("✔ No lint issues found.", fg="green")
        else:
            click.secho(f"✖ {result.to_dict()['issue_count']} issue(s) found:", fg="red")
            for issue in result.issues:
                click.echo(
                    f"  [{issue.check}] {issue.environment}/{issue.key}: {issue.message}"
                )

    if fail_on_issues and not result.passed:
        raise SystemExit(1)


@lint_group.command("checks")
def checks_cmd():
    """List all available lint checks."""
    from envault.lint import LINT_CHECKS
    for check in LINT_CHECKS:
        click.echo(f"  - {check}")
