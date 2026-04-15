"""Tests for envault.cli_template."""
from __future__ import annotations

import pytest
from click.testing import CliRunner

from envault.cli_template import template_group


# ---------------------------------------------------------------------------
# Fakes / fixtures
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str):
        self.value = value


class _FakeVault:
    def __init__(self, secrets: dict):
        self._secrets = secrets

    def get_secret(self, environment: str, key: str):
        v = self._secrets.get((environment, key))
        return _FakeEntry(v) if v is not None else None


@pytest.fixture()
def runner():
    return CliRunner(mix_stderr=False)


def _patch_vault(monkeypatch, secrets: dict):
    fake = _FakeVault(secrets)
    monkeypatch.setattr("envault.cli_template._get_vault", lambda *a, **kw: fake)


# ---------------------------------------------------------------------------
# render command
# ---------------------------------------------------------------------------

def test_render_resolves_secret(runner, monkeypatch):
    _patch_vault(monkeypatch, {("prod", "TOKEN"): "abc123"})
    result = runner.invoke(
        template_group,
        ["render", "token={{ TOKEN }}", "--env", "prod",
         "--passphrase", "x"],
    )
    assert result.exit_code == 0
    assert "abc123" in result.output


def test_render_uses_default(runner, monkeypatch):
    _patch_vault(monkeypatch, {})
    result = runner.invoke(
        template_group,
        ["render", "val={{ MISSING:fallback }}", "--env", "dev",
         "--passphrase", "x"],
    )
    assert result.exit_code == 0
    assert "fallback" in result.output


def test_render_strict_fails_on_missing(runner, monkeypatch):
    _patch_vault(monkeypatch, {})
    result = runner.invoke(
        template_group,
        ["render", "{{ UNKNOWN }}", "--env", "dev",
         "--passphrase", "x", "--strict"],
    )
    assert result.exit_code != 0


def test_render_show_missing_flag(runner, monkeypatch):
    _patch_vault(monkeypatch, {})
    result = runner.invoke(
        template_group,
        ["render", "{{ GONE }}", "--env", "dev",
         "--passphrase", "x", "--show-missing"],
    )
    assert result.exit_code == 0
    assert "GONE" in result.stderr


# ---------------------------------------------------------------------------
# render-file command
# ---------------------------------------------------------------------------

def test_render_file_stdout(runner, monkeypatch, tmp_path):
    _patch_vault(monkeypatch, {("staging", "DB"): "mydb"})
    tpl = tmp_path / "tpl.txt"
    tpl.write_text("db={{ DB }}")
    result = runner.invoke(
        template_group,
        ["render-file", str(tpl), "--env", "staging", "--passphrase", "x"],
    )
    assert result.exit_code == 0
    assert "mydb" in result.output


def test_render_file_to_output(runner, monkeypatch, tmp_path):
    _patch_vault(monkeypatch, {("prod", "KEY"): "val"})
    tpl = tmp_path / "tpl.txt"
    tpl.write_text("key={{ KEY }}")
    out = tmp_path / "out.txt"
    result = runner.invoke(
        template_group,
        ["render-file", str(tpl), "--env", "prod",
         "--passphrase", "x", "--output", str(out)],
    )
    assert result.exit_code == 0
    assert out.read_text() == "key=val"
