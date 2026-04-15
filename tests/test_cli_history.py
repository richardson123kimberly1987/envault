"""Tests for envault.cli_history."""
import json
import pytest
from click.testing import CliRunner

from envault.cli_history import history_group


# ---------------------------------------------------------------------------
# Shared fakes
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str = "enc_val"):
        self._value = value

    def to_dict(self):
        return {"value": self._value}


class _FakeVault:
    def __init__(self):
        self._data: dict = {}
        self._secrets: dict = {}

    def get_secret(self, env, key):
        return self._secrets.get((env, key))

    def save(self):
        pass


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def runner():
    return CliRunner()


@pytest.fixture()
def patched_vault(monkeypatch):
    fake = _FakeVault()
    monkeypatch.setattr("envault.cli_history._get_vault", lambda *a, **kw: fake)
    return fake


# ---------------------------------------------------------------------------
# record command
# ---------------------------------------------------------------------------

def test_record_missing_secret_shows_error(runner, patched_vault):
    result = runner.invoke(
        history_group,
        ["record", "prod", "MISSING", "--passphrase", "pass"],
    )
    assert result.exit_code != 0
    assert "not found" in result.output.lower() or "Error" in result.output


def test_record_existing_secret_outputs_version(runner, patched_vault):
    patched_vault._secrets[("prod", "DB_PASS")] = _FakeEntry("secret")
    result = runner.invoke(
        history_group,
        ["record", "prod", "DB_PASS", "--passphrase", "pass", "--by", "tester"],
    )
    assert result.exit_code == 0
    assert "version 1" in result.output
    assert "DB_PASS" in result.output


# ---------------------------------------------------------------------------
# list command
# ---------------------------------------------------------------------------

def test_list_no_history(runner, patched_vault):
    result = runner.invoke(
        history_group,
        ["list", "dev", "API_KEY", "--passphrase", "pass"],
    )
    assert result.exit_code == 0
    assert "No history" in result.output


def test_list_shows_entries(runner, patched_vault):
    patched_vault._secrets[("dev", "API_KEY")] = _FakeEntry("v1")
    from envault.history import record_history
    record_history(patched_vault, "dev", "API_KEY", updated_by="alice")
    patched_vault._secrets[("dev", "API_KEY")] = _FakeEntry("v2")
    record_history(patched_vault, "dev", "API_KEY", updated_by="bob")

    result = runner.invoke(
        history_group,
        ["list", "dev", "API_KEY", "--passphrase", "pass"],
    )
    assert result.exit_code == 0
    assert "v2" in result.output
    assert "v1" in result.output
    assert "bob" in result.output


def test_list_limit(runner, patched_vault):
    patched_vault._secrets[("dev", "TOKEN")] = _FakeEntry("x")
    from envault.history import record_history
    for _ in range(4):
        record_history(patched_vault, "dev", "TOKEN")

    result = runner.invoke(
        history_group,
        ["list", "dev", "TOKEN", "--passphrase", "pass", "--limit", "2"],
    )
    assert result.exit_code == 0
    # Only 2 version lines should appear (v4 and v3)
    lines = [l for l in result.output.splitlines() if l.strip().startswith("v")]
    assert len(lines) == 2
