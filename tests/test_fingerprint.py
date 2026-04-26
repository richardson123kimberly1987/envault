"""Tests for envault.fingerprint."""
import pytest

from envault.fingerprint import (
    FINGERPRINT_ALGORITHMS,
    FingerprintError,
    FingerprintResult,
    fingerprint_secret,
    verify_fingerprint,
)


class _FakeEntry:
    def __init__(self, value: str):
        self._value = value

    def to_dict(self):
        return {"value": self._value}


class _FakeVault:
    def __init__(self, secrets: dict):
        # secrets: {(key, env): value}
        self._secrets = secrets

    def get_secret(self, key, environment):
        entry_value = self._secrets.get((key, environment))
        if entry_value is None:
            return None
        return _FakeEntry(entry_value)


@pytest.fixture
def vault():
    return _FakeVault({
        ("API_KEY", "production"): "super-secret-value",
        ("DB_PASS", "staging"): "another-secret",
    })


def test_fingerprint_algorithms_constant_not_empty():
    assert len(FINGERPRINT_ALGORITHMS) > 0
    assert "sha256" in FINGERPRINT_ALGORITHMS


def test_fingerprint_result_to_dict(vault):
    result = fingerprint_secret(vault, "API_KEY", "production")
    d = result.to_dict()
    assert d["key"] == "API_KEY"
    assert d["environment"] == "production"
    assert d["algorithm"] == "sha256"
    assert isinstance(d["fingerprint"], str)
    assert len(d["fingerprint"]) == 64  # sha256 hex length


def test_fingerprint_is_deterministic(vault):
    r1 = fingerprint_secret(vault, "API_KEY", "production")
    r2 = fingerprint_secret(vault, "API_KEY", "production")
    assert r1.fingerprint == r2.fingerprint


def test_fingerprint_differs_by_value(vault):
    r1 = fingerprint_secret(vault, "API_KEY", "production")
    r2 = fingerprint_secret(vault, "DB_PASS", "staging")
    assert r1.fingerprint != r2.fingerprint


def test_fingerprint_sha512_algorithm(vault):
    result = fingerprint_secret(vault, "API_KEY", "production", algorithm="sha512")
    assert result.algorithm == "sha512"
    assert len(result.fingerprint) == 128  # sha512 hex length


def test_fingerprint_unsupported_algorithm_raises(vault):
    with pytest.raises(FingerprintError, match="Unsupported algorithm"):
        fingerprint_secret(vault, "API_KEY", "production", algorithm="blake2b")


def test_fingerprint_missing_secret_raises(vault):
    with pytest.raises(FingerprintError, match="not found"):
        fingerprint_secret(vault, "MISSING_KEY", "production")


def test_verify_fingerprint_matched(vault):
    result = fingerprint_secret(vault, "API_KEY", "production")
    verification = verify_fingerprint(
        vault, "API_KEY", "production", expected=result.fingerprint
    )
    assert verification.matched is True


def test_verify_fingerprint_not_matched(vault):
    verification = verify_fingerprint(
        vault, "API_KEY", "production", expected="deadbeef" * 8
    )
    assert verification.matched is False


def test_verify_fingerprint_missing_secret_raises(vault):
    with pytest.raises(FingerprintError):
        verify_fingerprint(vault, "NO_SUCH", "production", expected="abc")
