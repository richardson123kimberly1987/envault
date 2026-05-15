"""Tests for envault.replay."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional
from unittest.mock import MagicMock

import pytest

from envault.audit import AuditEvent
from envault.replay import ReplayError, ReplayResult, replay_events


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _event(action: str, key: str = "MY_KEY", value: str = "v", env: str = "prod") -> AuditEvent:
    return AuditEvent(
        action=action,
        timestamp=datetime.now(timezone.utc).isoformat(),
        metadata={"key": key, "value": value, "environment": env},
    )


def _make_audit_log(events: List[AuditEvent]):
    log = MagicMock()
    log.load.return_value = events
    return log


def _make_vault() -> MagicMock:
    vault = MagicMock()
    vault.set_secret = MagicMock()
    return vault


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_replay_result_to_dict():
    result = ReplayResult(replayed=3, skipped=1, events=[{"action": "set"}])
    d = result.to_dict()
    assert d["replayed"] == 3
    assert d["skipped"] == 1
    assert len(d["events"]) == 1


def test_replay_applies_set_events():
    events = [_event("set", key="A", value="1"), _event("set", key="B", value="2")]
    audit = _make_audit_log(events)
    vault = _make_vault()

    result = replay_events(audit, vault)

    assert result.replayed == 2
    assert result.skipped == 0
    assert vault.set_secret.call_count == 2


def test_replay_skips_non_set_events():
    events = [_event("get"), _event("delete"), _event("set", key="K", value="v")]
    audit = _make_audit_log(events)
    vault = _make_vault()

    result = replay_events(audit, vault)

    assert result.replayed == 1
    assert result.skipped == 2


def test_replay_filters_by_environment():
    events = [
        _event("set", key="A", value="1", env="prod"),
        _event("set", key="B", value="2", env="staging"),
    ]
    audit = _make_audit_log(events)
    vault = _make_vault()

    result = replay_events(audit, vault, environment="prod")

    assert result.replayed == 1
    assert result.skipped == 1


def test_replay_dry_run_does_not_call_vault():
    events = [_event("set", key="X", value="y")]
    audit = _make_audit_log(events)
    vault = _make_vault()

    result = replay_events(audit, vault, dry_run=True)

    assert result.replayed == 1
    vault.set_secret.assert_not_called()


def test_replay_skips_events_without_key():
    bad = AuditEvent(
        action="set",
        timestamp=datetime.now(timezone.utc).isoformat(),
        metadata={"value": "v"},
    )
    audit = _make_audit_log([bad])
    vault = _make_vault()

    result = replay_events(audit, vault)

    assert result.replayed == 0
    assert result.skipped == 1


def test_replay_custom_action_filter():
    events = [_event("rotate", key="K", value="new"), _event("set", key="K", value="old")]
    audit = _make_audit_log(events)
    vault = _make_vault()

    result = replay_events(audit, vault, action_filter="rotate")

    assert result.replayed == 1
    assert result.skipped == 1
