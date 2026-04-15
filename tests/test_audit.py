"""Tests for envault.audit module."""

import json
import pytest
from pathlib import Path

from envault.audit import AuditLog, AuditEvent, AUDIT_EVENTS


@pytest.fixture
def log_file(tmp_path: Path) -> Path:
    return tmp_path / "audit.log"


@pytest.fixture
def audit(log_file: Path) -> AuditLog:
    return AuditLog(log_file)


def test_audit_events_constant_not_empty():
    assert len(AUDIT_EVENTS) > 0
    assert "set" in AUDIT_EVENTS
    assert "get" in AUDIT_EVENTS


def test_record_creates_log_file(audit: AuditLog, log_file: Path):
    audit.record("set", "API_KEY", "production")
    assert log_file.exists()


def test_record_returns_audit_event(audit: AuditLog):
    entry = audit.record("get", "DB_PASS", "staging")
    assert isinstance(entry, AuditEvent)
    assert entry.event == "get"
    assert entry.key == "DB_PASS"
    assert entry.environment == "staging"


def test_record_unknown_event_raises(audit: AuditLog):
    with pytest.raises(ValueError, match="Unknown audit event"):
        audit.record("unknown_event", "KEY", "dev")


def test_record_stores_metadata(audit: AuditLog):
    audit.record("rotate", "TOKEN", "production", reason="scheduled")
    events = audit.read()
    assert events[0].metadata == {"reason": "scheduled"}


def test_read_returns_all_events(audit: AuditLog):
    audit.record("set", "A", "dev")
    audit.record("get", "B", "staging")
    audit.record("delete", "C", "production")
    assert len(audit.read()) == 3


def test_read_filters_by_environment(audit: AuditLog):
    audit.record("set", "A", "dev")
    audit.record("set", "B", "production")
    results = audit.read(environment="dev")
    assert len(results) == 1
    assert results[0].key == "A"


def test_read_filters_by_event(audit: AuditLog):
    audit.record("set", "A", "dev")
    audit.record("get", "A", "dev")
    results = audit.read(event="get")
    assert len(results) == 1
    assert results[0].event == "get"


def test_read_empty_log_returns_empty_list(audit: AuditLog):
    assert audit.read() == []


def test_clear_removes_log(audit: AuditLog, log_file: Path):
    audit.record("set", "KEY", "dev")
    audit.clear()
    assert not log_file.exists()
    assert audit.read() == []


def test_log_file_is_valid_jsonl(audit: AuditLog, log_file: Path):
    audit.record("export", "ALL", "staging", format="dotenv")
    lines = log_file.read_text().strip().splitlines()
    assert len(lines) == 1
    data = json.loads(lines[0])
    assert data["event"] == "export"
    assert data["key"] == "ALL"
