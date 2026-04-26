"""CLI commands for the template feature."""
from __future__ import annotations

import sys

import click

from envault.cli import _get_vault
from envault.template import TemplateError, render_template


@click.group("template", help="Render secret templates.")
def template_group() -> None:
    pass


@template_group.command("render")
@click.argument("template_text")
@click.option("--env", "environment", required=True, help="Environment to resolve secrets from.")
@click.option("--vault-file", default="vault.json", show_default=True, help="Path to vault file.")
@click.option("--passphrase", prompt=True, hide_input=True, help="Vault passphrase.")
@click.option("--strict", is_flag=True, default=False, help="Fail on unresolved placeholders.")
@click.option("--show-missing", is_flag=True, default=False, help="Print missing keys to stderr.")
def render_cmd(
    template_text: str,
    environment: str,
    vault_file: str,
    passphrase: str,
    strict: bool,
    show_missing: bool,
) -> None:
    """Render TEMPLATE_TEXT, substituting {{ KEY }} placeholders from the vault."""
    vault = _get_vault(vault_file, passphrase)
    try:
        result = render_template(template_text, vault, environment, strict=strict)
    except TemplateError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    click.echo(result.rendered)

    if show_missing and result.missing:
        click.echo(f"Missing secrets: {', '.join(result.missing)}", err=True)


@template_group.command("render-file")
@click.argument("template_file", type=click.Path(exists=True, readable=True))
@click.option("--env", "environment", required=True, help="Environment to resolve secrets from.")
@click.option("--vault-file", default="vault.json", show_default=True)
@click.option("--passphrase", prompt=True, hide_input=True)
@click.option("--strict", is_flag=True, default=False)
@click.option("--show-missing", is_flag=True, default=False, help="Print missing keys to stderr.")
@click.option("--output", "-o", default="-", help="Output file (default: stdout).")
def render_file_cmd(
    template_file: str,
    environment: str,
    vault_file: str,
    passphrase: str,
    strict: bool,
    show_missing: bool,
    output: str,
) -> None:
    """Render a template FILE, writing the result to OUTPUT."""
    with open(template_file, "r", encoding="utf-8") as fh:
        template_text = fh.read()

    vault = _get_vault(vault_file, passphrase)
    try:
        result = render_template(template_text, vault, environment, strict=strict)
    except TemplateError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    if output == "-":
        click.echo(result.rendered, nl=False)
    else:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(result.rendered)
        click.echo(f"Written to {output}")

    if show_missing and result.missing:
        click.echo(f"Missing secrets: {', '.join(result.missing)}", err=True)
