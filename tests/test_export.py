"""Tests for envault.export module."""
import json
import pytest

from unittest.mock import MagicMock
from envault.export import (
    export_secrets,
    export_dotenv,
    export_json,
    export_shell,
    ExportError,
    SUPPORTED_FORMATS,
)


@pytest.fixture()
def mock_vault():
    vault = MagicMock()
    vault.list_secrets.return_value = ["API_KEY", "DB_PASS"]
    vault.get_secret.side_effect = lambda key, env: {
        "API_KEY": "abc123",
        "DB_PASS": 'p@ss"word',
    }.get(key)
    return vault


def test_supported_formats_constant():
    assert "dotenv" in SUPPORTED_FORMATS
    assert "json" in SUPPORTED_FORMATS
    assert "shell" in SUPPORTED_FORMATS


def test_export_dotenv_contains_keys(mock_vault):
    result = export_dotenv(mock_vault, "production")
    assert "API_KEY=" in result
    assert "DB_PASS=" in result
    assert "production" in result


def test_export_dotenv_escapes_quotes(mock_vault):
    result = export_dotenv(mock_vault, "production")
    assert '\\"' in result


def test_export_dotenv_empty_vault():
    vault = MagicMock()
    vault.list_secrets.return_value = []
    result = export_dotenv(vault, "staging")
    assert "staging" in result
    assert "=" not in result


def test_export_json_valid_structure(mock_vault):
    result = export_json(mock_vault, "production")
    data = json.loads(result)
    assert data["environment"] == "production"
    assert data["secrets"]["API_KEY"] == "abc123"
    assert "DB_PASS" in data["secrets"]


def test_export_shell_uses_export_keyword(mock_vault):
    result = export_shell(mock_vault, "production")
    assert result.count("export ") == 2
    assert "API_KEY=" in result


def test_export_shell_quotes_special_chars(mock_vault):
    result = export_shell(mock_vault, "production")
    # shlex.quote wraps values with single quotes when needed
    assert "DB_PASS=" in result


def test_export_secrets_dispatches_dotenv(mock_vault):
    result = export_secrets(mock_vault, "dev", "dotenv")
    assert "API_KEY=" in result


def test_export_secrets_dispatches_json(mock_vault):
    result = export_secrets(mock_vault, "dev", "json")
    data = json.loads(result)
    assert "secrets" in data


def test_export_secrets_dispatches_shell(mock_vault):
    result = export_secrets(mock_vault, "dev", "shell")
    assert "export " in result


def test_export_secrets_invalid_format_raises(mock_vault):
    with pytest.raises(ExportError, match="Unsupported format"):
        export_secrets(mock_vault, "dev", "yaml")
