"""CLI commands for managing notification webhooks."""
from __future__ import annotations

import json
from pathlib import Path

import click

from envault.notify import NOTIFY_EVENTS, NotifyConfig, send_notification

_CONFIG_FILE = Path("envault_notify.json")


def _load_configs():
    if not _CONFIG_FILE.exists():
        return []
    return [NotifyConfig.from_dict(d) for d in json.loads(_CONFIG_FILE.read_text())]


def _save_configs(configs):
    _CONFIG_FILE.write_text(json.dumps([c.to_dict() for c in configs], indent=2))


@click.group("notify", help="Manage webhook notifications for secret events.")
def notify_group():
    pass


@notify_group.command("add")
@click.argument("webhook_url")
@click.option("--events", default=",".join(NOTIFY_EVENTS), show_default=True, help="Comma-separated events.")
@click.option("--timeout", default=5, show_default=True, type=int)
def add_cmd(webhook_url, events, timeout):
    """Register a webhook URL."""
    event_list = [e.strip() for e in events.split(",") if e.strip()]
    cfg = NotifyConfig(webhook_url=webhook_url, events=event_list, timeout=timeout)
    configs = _load_configs()
    configs.append(cfg)
    _save_configs(configs)
    click.echo(f"Webhook registered: {webhook_url}")


@notify_group.command("list")
def list_cmd():
    """List registered webhooks."""
    configs = _load_configs()
    if not configs:
        click.echo("No webhooks registered.")
        return
    for i, c in enumerate(configs):
        click.echo(f"[{i}] {c.webhook_url}  events={c.events}  timeout={c.timeout}s")


@notify_group.command("remove")
@click.argument("index", type=int)
def remove_cmd(index):
    """Remove a webhook by index."""
    configs = _load_configs()
    if index < 0 or index >= len(configs):
        raise click.ClickException(f"Index {index} out of range.")
    removed = configs.pop(index)
    _save_configs(configs)
    click.echo(f"Removed webhook: {removed.webhook_url}")


@notify_group.command("test")
@click.argument("index", type=int)
@click.option("--secret", default="TEST_SECRET", show_default=True)
@click.option("--env", "environment", default="dev", show_default=True)
def test_cmd(index, secret, environment):
    """Send a test 'set' notification to a registered webhook."""
    configs = _load_configs()
    if index < 0 or index >= len(configs):
        raise click.ClickException(f"Index {index} out of range.")
    result = send_notification(configs[index], "set", secret, environment, extra={"test": True})
    if result.success:
        click.echo(f"Notification sent (status {result.status_code}).")
    else:
        raise click.ClickException(f"Notification failed: {result.error}")
