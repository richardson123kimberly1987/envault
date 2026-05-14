"""Tests for envault.cipher and envault.cli_cipher."""
from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from envault.cipher import (
    CIPHER_SUITES,
    DEFAULT_CIPHER,
    CipherError,
    CipherInfo,
    get_cipher_info,
    list_ciphers,
)
from envault.cli_cipher import cipher_group


# ---------------------------------------------------------------------------
# Unit tests for envault.cipher
# ---------------------------------------------------------------------------


def test_cipher_suites_not_empty():
    assert len(CIPHER_SUITES) > 0


def test_default_cipher_in_suites():
    assert DEFAULT_CIPHER in CIPHER_SUITES


def test_get_cipher_info_returns_cipher_info():
    info = get_cipher_info(DEFAULT_CIPHER)
    assert isinstance(info, CipherInfo)
    assert info.name == DEFAULT_CIPHER
    assert info.is_default is True


def test_get_cipher_info_case_insensitive():
    info = get_cipher_info(DEFAULT_CIPHER.lower())
    assert info.name == DEFAULT_CIPHER


def test_get_cipher_info_unknown_raises():
    with pytest.raises(CipherError, match="Unknown cipher suite"):
        get_cipher_info("ROT13")


def test_cipher_info_to_dict_keys():
    info = get_cipher_info(DEFAULT_CIPHER)
    d = info.to_dict()
    for key in ("name", "key_bits", "mode", "authenticated", "description", "is_default"):
        assert key in d


def test_list_ciphers_length():
    ciphers = list_ciphers()
    assert len(ciphers) == len(CIPHER_SUITES)


def test_list_ciphers_exactly_one_default():
    defaults = [c for c in list_ciphers() if c.is_default]
    assert len(defaults) == 1


def test_non_default_cipher_is_default_false():
    non_defaults = [c for c in list_ciphers() if not c.is_default]
    assert len(non_defaults) == len(CIPHER_SUITES) - 1


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------


@pytest.fixture()
def runner():
    return CliRunner()


def test_cli_list_plain(runner):
    result = runner.invoke(cipher_group, ["list"])
    assert result.exit_code == 0
    assert DEFAULT_CIPHER in result.output


def test_cli_list_json(runner):
    result = runner.invoke(cipher_group, ["list", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert isinstance(data, list)
    assert len(data) == len(CIPHER_SUITES)


def test_cli_info_known(runner):
    result = runner.invoke(cipher_group, ["info", DEFAULT_CIPHER])
    assert result.exit_code == 0
    assert DEFAULT_CIPHER in result.output


def test_cli_info_json(runner):
    result = runner.invoke(cipher_group, ["info", DEFAULT_CIPHER, "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["name"] == DEFAULT_CIPHER
    assert data["is_default"] is True


def test_cli_info_unknown_exits_nonzero(runner):
    result = runner.invoke(cipher_group, ["info", "ROT13"])
    assert result.exit_code != 0
    assert "Error" in result.output or "Error" in (result.output + str(result.exception))
