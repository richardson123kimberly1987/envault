"""Tests for envault.encode."""

from __future__ import annotations

import base64
import pytest

from envault.encode import (
    ENCODE_FORMATS,
    EncodeError,
    EncodeResult,
    decode_secret,
    encode_secret,
)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str) -> None:
        self._value = value

    def decrypt(self, passphrase: str) -> str:  # noqa: ARG002
        return self._value

    def to_dict(self) -> dict:
        return {"value": self._value}


class _FakeVault:
    def __init__(self, secrets: dict[tuple[str, str], str]) -> None:
        self._secrets = secrets

    def get_secret(self, environment: str, secret: str):
        val = self._secrets.get((environment, secret))
        return _FakeEntry(val) if val is not None else None


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def test_encode_formats_constant_not_empty():
    assert len(ENCODE_FORMATS) > 0


def test_encode_formats_contains_base64():
    assert "base64" in ENCODE_FORMATS


# ---------------------------------------------------------------------------
# encode_secret
# ---------------------------------------------------------------------------

def test_encode_base64_round_trip():
    vault = _FakeVault({("prod", "KEY"): "hello"})
    result = encode_secret(vault, "prod", "KEY", "base64", "pass")
    assert result.encoded == base64.b64encode(b"hello").decode()
    assert result.original == "hello"


def test_encode_hex():
    vault = _FakeVault({("prod", "KEY"): "hello"})
    result = encode_secret(vault, "prod", "KEY", "hex", "pass")
    assert result.encoded == b"hello".hex()


def test_encode_urlsafe():
    vault = _FakeVault({("prod", "KEY"): "hello+world"})
    result = encode_secret(vault, "prod", "KEY", "urlsafe", "pass")
    assert result.encoded == base64.urlsafe_b64encode(b"hello+world").decode()


def test_encode_missing_secret_raises():
    vault = _FakeVault({})
    with pytest.raises(EncodeError, match="not found"):
        encode_secret(vault, "prod", "MISSING", "base64", "pass")


def test_encode_unsupported_format_raises():
    vault = _FakeVault({("prod", "KEY"): "hello"})
    with pytest.raises(EncodeError, match="Unsupported format"):
        encode_secret(vault, "prod", "KEY", "rot13", "pass")


def test_encode_result_to_dict():
    vault = _FakeVault({("prod", "KEY"): "hi"})
    result = encode_secret(vault, "prod", "KEY", "hex", "pass")
    d = result.to_dict()
    assert d["secret"] == "KEY"
    assert d["format"] == "hex"
    assert "encoded" in d


# ---------------------------------------------------------------------------
# decode_secret
# ---------------------------------------------------------------------------

def test_decode_base64():
    encoded_val = base64.b64encode(b"secret").decode()
    vault = _FakeVault({("prod", "KEY"): encoded_val})
    result = decode_secret(vault, "prod", "KEY", "base64", "pass")
    assert result.encoded == "secret"


def test_decode_hex():
    hex_val = b"secret".hex()
    vault = _FakeVault({("prod", "KEY"): hex_val})
    result = decode_secret(vault, "prod", "KEY", "hex", "pass")
    assert result.encoded == "secret"


def test_decode_invalid_base64_raises():
    vault = _FakeVault({("prod", "KEY"): "!!!not_valid_base64!!!"})
    with pytest.raises(EncodeError, match="Failed to decode"):
        decode_secret(vault, "prod", "KEY", "base64", "pass")


def test_decode_missing_secret_raises():
    vault = _FakeVault({})
    with pytest.raises(EncodeError, match="not found"):
        decode_secret(vault, "prod", "MISSING", "base64", "pass")
