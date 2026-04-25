"""CLI commands for managing webhooks in envault."""
from __future__ import annotations

import json
from pathlib import Path
from typing import List

import click

from envault.webhook import (
    WEBHOOK_EVENTS,
    WebhookConfig,
    WebhookError,
    deliver_webhook,
)

_WEBHOOKS_FILE = Path(".envault_webhooks.json")


def _load_configs() -> List[WebhookConfig]:
    if not _WEBHOOKS_FILE.exists():
        return []
    data = json.loads(_WEBHOOKS_FILE.read_text())
    return [WebhookConfig.from_dict(d) for d in data]


def _save_configs(configs: List[WebhookConfig]) -> None:
    _WEBHOOKS_FILE.write_text(json.dumps([c.to_dict() for c in configs], indent=2))


@click.group("webhook")
def webhook_group() -> None:
    """Manage webhook delivery endpoints."""


@webhook_group.command("add")
@click.argument("url")
@click.option("--event", "events", multiple=True, help="Event to subscribe to (repeatable).")
@click.option("--secret", default=None, help="HMAC signing secret.")
def add_cmd(url: str, events: tuple, secret: str) -> None:
    """Register a new webhook endpoint."""
    chosen = list(events) if events else list(WEBHOOK_EVENTS)
    for ev in chosen:
        if ev not in WEBHOOK_EVENTS:
            raise click.ClickException(f"Unknown event {ev!r}. Valid: {WEBHOOK_EVENTS}")
    configs = _load_configs()
    configs.append(WebhookConfig(url=url, events=chosen, secret=secret))
    _save_configs(configs)
    click.echo(f"Webhook added: {url} ({', '.join(chosen)})")


@webhook_group.command("list")
def list_cmd() -> None:
    """List registered webhook endpoints."""
    configs = _load_configs()
    if not configs:
        click.echo("No webhooks registered.")
        return
    for cfg in configs:
        events_str = ", ".join(cfg.events) if cfg.events else "all"
        signed = " [signed]" if cfg.secret else ""
        click.echo(f"  {cfg.url}  events=[{events_str}]{signed}")


@webhook_group.command("remove")
@click.argument("url")
def remove_cmd(url: str) -> None:
    """Remove a webhook endpoint by URL."""
    configs = _load_configs()
    new = [c for c in configs if c.url != url]
    if len(new) == len(configs):
        raise click.ClickException(f"No webhook found for URL: {url}")
    _save_configs(new)
    click.echo(f"Webhook removed: {url}")


@webhook_group.command("test")
@click.argument("url")
@click.option("--event", default="secret.set", show_default=True)
def test_cmd(url: str, event: str) -> None:
    """Send a test payload to a webhook URL."""
    configs = _load_configs()
    cfg = next((c for c in configs if c.url == url), WebhookConfig(url=url))
    try:
        result = deliver_webhook(cfg, event, {"test": True})
    except WebhookError as exc:
        raise click.ClickException(str(exc))
    if result.delivered:
        click.echo(f"Delivered ({result.status_code}): {url}")
    else:
        click.echo(f"Failed ({result.status_code}): {result.error}")
