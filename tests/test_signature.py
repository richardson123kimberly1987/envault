"""Tests for envault.signature."""
from __future__ import annotations

import pytest

from envault.signature import (
    SignatureError,
    SignatureResult,
    sign_secret,
    verify_secret,
    SIGNATURE_ALGORITHM,
)


class _FakeEntry:
    def __init__(self, value: str):
        self._value = value

    def to_dict(self):
        return {"value": self._value}


class _FakeVault:
    def __init__(self, secrets: dict):
        # secrets: {(env, key): value_str}
        self._secrets = secrets

    def get_secret(self, environment: str, key: str):
        val = self._secrets.get((environment, key))
        return _FakeEntry(val) if val is not None else None


@pytest.fixture
def vault():
    return _FakeVault({
        ("prod", "DB_PASSWORD"): "s3cr3t",
        ("staging", "API_KEY"): "abc123",
    })


def test_signature_algorithm_constant():
    assert SIGNATURE_ALGORITHM == "sha256"


def test_sign_returns_signature_result(vault):
    result = sign_secret(vault, "prod", "DB_PASSWORD", "passphrase")
    assert isinstance(result, SignatureResult)
    assert result.key == "DB_PASSWORD"
    assert result.environment == "prod"
    assert result.algorithm == "sha256"
    assert len(result.signature) == 64  # hex SHA-256
    assert result.verified is True


def test_sign_missing_secret_raises(vault):
    with pytest.raises(SignatureError, match="not found"):
        sign_secret(vault, "prod", "MISSING", "passphrase")


def test_sign_different_passphrases_produce_different_signatures(vault):
    r1 = sign_secret(vault, "prod", "DB_PASSWORD", "pass1")
    r2 = sign_secret(vault, "prod", "DB_PASSWORD", "pass2")
    assert r1.signature != r2.signature


def test_verify_correct_signature(vault):
    signed = sign_secret(vault, "prod", "DB_PASSWORD", "passphrase")
    result = verify_secret(vault, "prod", "DB_PASSWORD", "passphrase", signed.signature)
    assert result.verified is True


def test_verify_wrong_signature(vault):
    result = verify_secret(vault, "prod", "DB_PASSWORD", "passphrase", "deadbeef" * 8)
    assert result.verified is False


def test_verify_missing_secret_raises(vault):
    with pytest.raises(SignatureError, match="not found"):
        verify_secret(vault, "prod", "MISSING", "passphrase", "abc")


def test_signature_result_to_dict(vault):
    result = sign_secret(vault, "staging", "API_KEY", "mypass")
    d = result.to_dict()
    assert d["key"] == "API_KEY"
    assert d["environment"] == "staging"
    assert d["algorithm"] == "sha256"
    assert "signature" in d
    assert d["verified"] is True


def test_sign_deterministic_for_same_inputs(vault):
    r1 = sign_secret(vault, "prod", "DB_PASSWORD", "stable")
    r2 = sign_secret(vault, "prod", "DB_PASSWORD", "stable")
    assert r1.signature == r2.signature
