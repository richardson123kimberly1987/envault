"""Tests for envault.cli_lifecycle."""
from __future__ import annotations

import pytest
from click.testing import CliRunner

from envault.cli_lifecycle import lifecycle_group


class _FakeEntry:
    def __init__(self, value: str, stage: str = "active"):
        self._data = {"value": value, "lifecycle_stage": stage}

    def to_dict(self):
        return dict(self._data)


class _FakeVault:
    def __init__(self):
        self._store: dict[tuple, _FakeEntry] = {}
        self.saved = False

    def get_secret(self, env, name):
        return self._store.get((env, name))

    def set_secret(self, env, name, value, metadata=None):
        stage = (metadata or {}).get("lifecycle_stage", "active")
        self._store[(env, name)] = _FakeEntry(value, stage)

    def list_secrets(self, env):
        return [k[1] for k in self._store if k[0] == env]

    def save(self):
        self.saved = True


@pytest.fixture
def runner():
    return CliRunner()


def _invoke(runner, fake_vault, args):
    with runner.isolated_filesystem():
        import envault.cli_lifecycle as mod
        import envault.cli as cli_mod
        original = cli_mod._get_vault
        cli_mod._get_vault = lambda *a, **kw: fake_vault
        result = runner.invoke(lifecycle_group, args, catch_exceptions=False)
        cli_mod._get_vault = original
        return result


def test_set_stage_success(runner):
    vault = _FakeVault()
    vault.set_secret("prod", "API_KEY", "val")
    result = _invoke(runner, vault, ["set", "prod", "API_KEY", "deprecated",
                                     "--vault-file", "v.json", "--passphrase", "pw"])
    assert result.exit_code == 0
    assert "active -> deprecated" in result.output
    assert vault.saved


def test_set_stage_missing_secret_shows_error(runner):
    vault = _FakeVault()
    result = _invoke(runner, vault, ["set", "prod", "MISSING", "inactive",
                                     "--vault-file", "v.json", "--passphrase", "pw"])
    assert result.exit_code == 1


def test_get_stage_active(runner):
    vault = _FakeVault()
    vault.set_secret("prod", "MY_SECRET", "value")
    result = _invoke(runner, vault, ["get", "prod", "MY_SECRET",
                                     "--vault-file", "v.json", "--passphrase", "pw"])
    assert result.exit_code == 0
    assert "active" in result.output


def test_list_stage_empty(runner):
    vault = _FakeVault()
    result = _invoke(runner, vault, ["list", "prod", "archived",
                                     "--vault-file", "v.json", "--passphrase", "pw"])
    assert result.exit_code == 0
    assert "No secrets" in result.output


def test_list_stage_returns_names(runner):
    vault = _FakeVault()
    vault.set_secret("prod", "OLD_KEY", "x", metadata={"lifecycle_stage": "expired"})
    vault.set_secret("prod", "NEW_KEY", "y")
    result = _invoke(runner, vault, ["list", "prod", "expired",
                                     "--vault-file", "v.json", "--passphrase", "pw"])
    assert result.exit_code == 0
    assert "OLD_KEY" in result.output
    assert "NEW_KEY" not in result.output
