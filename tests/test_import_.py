"""Tests for envault.import_."""

from __future__ import annotations

import pytest

from envault.import_ import ImportError, import_dotenv, import_json, import_secrets


# ---------------------------------------------------------------------------
# Minimal fake vault
# ---------------------------------------------------------------------------

class _FakeVault:
    def __init__(self):
        self._store: dict = {}

    def get_secret(self, env: str, key: str):
        return self._store.get((env, key))

    def set_secret(self, env: str, key: str, value: str):
        self._store[(env, key)] = value


@pytest.fixture()
def vault():
    return _FakeVault()


# ---------------------------------------------------------------------------
# import_dotenv
# ---------------------------------------------------------------------------

def test_import_dotenv_basic(vault):
    result = import_dotenv("FOO=bar\nBAZ=qux\n", vault, "prod")
    assert result == {"FOO": "bar", "BAZ": "qux"}
    assert vault.get_secret("prod", "FOO") == "bar"


def test_import_dotenv_strips_double_quotes(vault):
    result = import_dotenv('KEY="hello world"', vault, "dev")
    assert result["KEY"] == "hello world"


def test_import_dotenv_strips_single_quotes(vault):
    result = import_dotenv("KEY='hello world'", vault, "dev")
    assert result["KEY"] == "hello world"


def test_import_dotenv_ignores_comments_and_blank_lines(vault):
    source = "\n# a comment\nFOO=1\n"
    result = import_dotenv(source, vault, "staging")
    assert list(result.keys()) == ["FOO"]


def test_import_dotenv_invalid_line_raises(vault):
    with pytest.raises(ImportError, match="Invalid .env syntax"):
        import_dotenv("NOT VALID LINE", vault, "prod")


def test_import_dotenv_no_overwrite_skips_existing(vault):
    vault.set_secret("prod", "FOO", "original")
    result = import_dotenv("FOO=new", vault, "prod", overwrite=False)
    assert result == {}
    assert vault.get_secret("prod", "FOO") == "original"


def test_import_dotenv_overwrite_replaces_existing(vault):
    vault.set_secret("prod", "FOO", "original")
    result = import_dotenv("FOO=new", vault, "prod", overwrite=True)
    assert result == {"FOO": "new"}
    assert vault.get_secret("prod", "FOO") == "new"


# ---------------------------------------------------------------------------
# import_json
# ---------------------------------------------------------------------------

def test_import_json_basic(vault):
    result = import_json('{"A": "1", "B": "2"}', vault, "prod")
    assert result == {"A": "1", "B": "2"}


def test_import_json_coerces_non_string_values(vault):
    result = import_json('{"PORT": 8080}', vault, "dev")
    assert result["PORT"] == "8080"


def test_import_json_invalid_json_raises(vault):
    with pytest.raises(ImportError, match="Invalid JSON"):
        import_json("not json", vault, "prod")


def test_import_json_non_object_raises(vault):
    with pytest.raises(ImportError, match="JSON root must be an object"):
        import_json("[1, 2, 3]", vault, "prod")


# ---------------------------------------------------------------------------
# import_secrets dispatcher
# ---------------------------------------------------------------------------

def test_import_secrets_dotenv(vault):
    result = import_secrets("X=10", "dotenv", vault, "prod")
    assert "X" in result


def test_import_secrets_json(vault):
    result = import_secrets('{"Y": "20"}', "json", vault, "prod")
    assert "Y" in result


def test_import_secrets_unknown_format_raises(vault):
    with pytest.raises(ImportError, match="Unsupported import format"):
        import_secrets("data", "toml", vault, "prod")
