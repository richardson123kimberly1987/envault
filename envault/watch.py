"""Watch secrets for changes and trigger callbacks."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

WATCH_EVENTS = ("added", "modified", "removed")


class WatchError(Exception):
    """Raised when a watch operation fails."""


@dataclass
class WatchEvent:
    environment: str
    key: str
    event_type: str  # 'added' | 'modified' | 'removed'
    old_value: Optional[str] = None
    new_value: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "environment": self.environment,
            "key": self.key,
            "event_type": self.event_type,
            "old_value": self.old_value,
            "new_value": self.new_value,
        }


def _snapshot(vault, environment: str) -> Dict[str, str]:
    """Return a {key: value} snapshot for the given environment."""
    result = {}
    for key in vault.list_secrets(environment):
        entry = vault.get_secret(environment, key)
        result[key] = entry.to_dict().get("value", "") if entry else ""
    return result


def diff_snapshots(
    environment: str,
    before: Dict[str, str],
    after: Dict[str, str],
) -> List[WatchEvent]:
    """Compare two snapshots and return a list of WatchEvents."""
    events: List[WatchEvent] = []
    all_keys = set(before) | set(after)
    for key in sorted(all_keys):
        if key not in before:
            events.append(WatchEvent(environment, key, "added", None, after[key]))
        elif key not in after:
            events.append(WatchEvent(environment, key, "removed", before[key], None))
        elif before[key] != after[key]:
            events.append(WatchEvent(environment, key, "modified", before[key], after[key]))
    return events


def watch_environment(
    vault,
    environment: str,
    callback: Callable[[WatchEvent], None],
    interval: float = 2.0,
    max_iterations: Optional[int] = None,
) -> None:
    """Poll *vault* for changes in *environment* and invoke *callback* for each.

    Runs until interrupted or *max_iterations* is reached (useful for tests).
    """
    if environment not in vault.list_environments():
        raise WatchError(f"Environment '{environment}' not found.")

    before = _snapshot(vault, environment)
    iterations = 0

    while True:
        if max_iterations is not None and iterations >= max_iterations:
            break
        time.sleep(interval)
        after = _snapshot(vault, environment)
        for event in diff_snapshots(environment, before, after):
            callback(event)
        before = after
        iterations += 1
