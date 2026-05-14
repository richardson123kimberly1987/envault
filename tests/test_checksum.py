"""Tests for envault.checksum."""
import pytest

from envault.checksum import (
    CHECKSUM_ALGORITHMS,
    ChecksumError,
    ChecksumResult,
    compute_checksum,
    verify_checksum,
)


class _FakeEntry:
    def __init__(self, value: str):
        self._value = value

    def decrypt(self) -> str:
        return self._value

    def to_dict(self):
        return {"value": self._value}


class _FakeVault:
    def __init__(self, secrets: dict):
        # secrets: {(env, name): value}
        self._secrets = secrets

    def get_secret(self, environment, name):
        key = (environment, name)
        if key not in self._secrets:
            return None
        return _FakeEntry(self._secrets[key])


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def test_checksum_algorithms_constant_not_empty():
    assert len(CHECKSUM_ALGORITHMS) > 0


# ---------------------------------------------------------------------------
# ChecksumResult.to_dict
# ---------------------------------------------------------------------------

def test_checksum_result_to_dict():
    r = ChecksumResult(
        secret_name="KEY",
        environment="prod",
        algorithm="sha256",
        checksum="abc123",
        verified=True,
    )
    d = r.to_dict()
    assert d["secret_name"] == "KEY"
    assert d["algorithm"] == "sha256"
    assert d["verified"] is True


# ---------------------------------------------------------------------------
# compute_checksum
# ---------------------------------------------------------------------------

def test_compute_checksum_returns_hex_string():
    vault = _FakeVault({("dev", "API_KEY"): "supersecret"})
    result = compute_checksum(vault, "dev", "API_KEY")
    assert isinstance(result.checksum, str)
    assert len(result.checksum) == 64  # sha256 hex length


def test_compute_checksum_sha512():
    vault = _FakeVault({("dev", "API_KEY"): "supersecret"})
    result = compute_checksum(vault, "dev", "API_KEY", algorithm="sha512")
    assert len(result.checksum) == 128


def test_compute_checksum_missing_secret_raises():
    vault = _FakeVault({})
    with pytest.raises(ChecksumError, match="not found"):
        compute_checksum(vault, "dev", "MISSING")


def test_compute_checksum_invalid_algorithm_raises():
    vault = _FakeVault({("dev", "KEY"): "value"})
    with pytest.raises(ChecksumError, match="Unsupported algorithm"):
        compute_checksum(vault, "dev", "KEY", algorithm="crc32")


def test_compute_checksum_deterministic():
    vault = _FakeVault({("dev", "KEY"): "hello"})
    r1 = compute_checksum(vault, "dev", "KEY")
    r2 = compute_checksum(vault, "dev", "KEY")
    assert r1.checksum == r2.checksum


# ---------------------------------------------------------------------------
# verify_checksum
# ---------------------------------------------------------------------------

def test_verify_checksum_correct():
    vault = _FakeVault({("prod", "DB_PASS"): "s3cr3t"})
    computed = compute_checksum(vault, "prod", "DB_PASS")
    result = verify_checksum(vault, "prod", "DB_PASS", computed.checksum)
    assert result.verified is True


def test_verify_checksum_wrong_value():
    vault = _FakeVault({("prod", "DB_PASS"): "s3cr3t"})
    result = verify_checksum(vault, "prod", "DB_PASS", "deadbeef")
    assert result.verified is False


def test_verify_checksum_missing_secret_raises():
    vault = _FakeVault({})
    with pytest.raises(ChecksumError):
        verify_checksum(vault, "prod", "GHOST", "abc")
