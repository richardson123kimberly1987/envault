"""Tests for envault.digest."""
from __future__ import annotations

import hashlib
import pytest

from envault.digest import (
    DIGEST_ALGORITHMS,
    DigestError,
    DigestResult,
    compute_digest,
    verify_digest,
)


class _FakeEntry:
    def __init__(self, value: str):
        self._value = value

    def decrypt(self) -> str:
        return self._value

    def to_dict(self) -> dict:
        return {"value": self._value}


class _FakeVault:
    def __init__(self, secrets: dict):
        # secrets: {(env, name): value}
        self._secrets = secrets

    def get_secret(self, environment: str, name: str):
        key = (environment, name)
        if key not in self._secrets:
            return None
        return _FakeEntry(self._secrets[key])


@pytest.fixture()
def vault():
    return _FakeVault({
        ("prod", "API_KEY"): "supersecret",
        ("dev", "DB_PASS"): "devpassword",
    })


def test_digest_algorithms_constant_not_empty():
    assert len(DIGEST_ALGORITHMS) > 0


def test_compute_digest_returns_result(vault):
    result = compute_digest(vault, "prod", "API_KEY")
    assert isinstance(result, DigestResult)
    assert result.secret_name == "API_KEY"
    assert result.environment == "prod"
    assert result.algorithm == "sha256"


def test_compute_digest_correct_value(vault):
    result = compute_digest(vault, "prod", "API_KEY", algorithm="sha256")
    expected = hashlib.sha256(b"supersecret").hexdigest()
    assert result.digest == expected


def test_compute_digest_sha512(vault):
    result = compute_digest(vault, "dev", "DB_PASS", algorithm="sha512")
    expected = hashlib.sha512(b"devpassword").hexdigest()
    assert result.digest == expected


def test_compute_digest_unsupported_algorithm_raises(vault):
    with pytest.raises(DigestError, match="Unsupported algorithm"):
        compute_digest(vault, "prod", "API_KEY", algorithm="blake2b")


def test_compute_digest_missing_secret_raises(vault):
    with pytest.raises(DigestError, match="not found"):
        compute_digest(vault, "prod", "MISSING")


def test_verify_digest_correct(vault):
    expected = hashlib.sha256(b"supersecret").hexdigest()
    result = verify_digest(vault, "prod", "API_KEY", expected)
    assert result.verified is True


def test_verify_digest_incorrect(vault):
    result = verify_digest(vault, "prod", "API_KEY", "deadbeef" * 8)
    assert result.verified is False


def test_digest_result_to_dict(vault):
    result = compute_digest(vault, "prod", "API_KEY")
    d = result.to_dict()
    assert d["secret_name"] == "API_KEY"
    assert d["environment"] == "prod"
    assert d["algorithm"] == "sha256"
    assert "digest" in d
    assert d["verified"] is None
