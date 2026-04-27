"""Tests for envault.benchmark."""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock

from envault.benchmark import (
    BENCHMARK_OPERATIONS,
    BenchmarkError,
    BenchmarkResult,
    benchmark_secret,
    benchmark_all,
)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str = "s3cr3t") -> None:
        self._value = value

    def to_dict(self):
        return {"value": self._value, "key": "FAKE_KEY"}


class _FakeVault:
    def __init__(self, secrets: dict[str, str] | None = None) -> None:
        self._secrets = secrets or {"API_KEY": "abc123", "DB_PASS": "hunter2"}

    def get_secret(self, key: str, environment: str):
        val = self._secrets.get(key)
        return _FakeEntry(val) if val is not None else None

    def list_secrets(self, environment: str):
        return list(self._secrets.keys())


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------

def test_benchmark_operations_constant_not_empty():
    assert len(BENCHMARK_OPERATIONS) > 0


def test_benchmark_result_to_dict():
    r = BenchmarkResult(
        operation="encrypt",
        iterations=10,
        total_seconds=0.05,
        min_seconds=0.004,
        max_seconds=0.008,
        avg_seconds=0.005,
        secret_key="KEY",
        environment="prod",
    )
    d = r.to_dict()
    assert d["operation"] == "encrypt"
    assert d["iterations"] == 10
    assert d["secret_key"] == "KEY"
    assert d["environment"] == "prod"
    assert isinstance(d["avg_seconds"], float)


def test_benchmark_secret_encrypt():
    vault = _FakeVault()
    result = benchmark_secret(vault, "API_KEY", "default", "encrypt", iterations=5)
    assert result.operation == "encrypt"
    assert result.iterations == 5
    assert result.secret_key == "API_KEY"
    assert result.total_seconds >= 0
    assert result.min_seconds <= result.max_seconds


def test_benchmark_secret_decrypt():
    vault = _FakeVault()
    result = benchmark_secret(vault, "API_KEY", "default", "decrypt", iterations=3)
    assert result.operation == "decrypt"
    assert result.iterations == 3


def test_benchmark_secret_hash():
    vault = _FakeVault()
    result = benchmark_secret(vault, "API_KEY", "default", "hash", iterations=3)
    assert result.operation == "hash"


def test_benchmark_secret_export():
    vault = _FakeVault()
    result = benchmark_secret(vault, "API_KEY", "default", "export", iterations=3)
    assert result.operation == "export"


def test_benchmark_secret_missing_key_raises():
    vault = _FakeVault()
    with pytest.raises(BenchmarkError, match="not found"):
        benchmark_secret(vault, "MISSING", "default")


def test_benchmark_secret_unknown_operation_raises():
    vault = _FakeVault()
    with pytest.raises(BenchmarkError, match="Unknown operation"):
        benchmark_secret(vault, "API_KEY", "default", operation="fly")


def test_benchmark_secret_zero_iterations_raises():
    vault = _FakeVault()
    with pytest.raises(BenchmarkError, match="iterations"):
        benchmark_secret(vault, "API_KEY", "default", iterations=0)


def test_benchmark_all_returns_results_for_each_secret():
    vault = _FakeVault()
    results = benchmark_all(vault, "default", "export", iterations=2)
    assert len(results) == len(vault._secrets)
    keys = {r.secret_key for r in results}
    assert keys == set(vault._secrets.keys())


def test_benchmark_all_empty_vault_returns_empty_list():
    vault = _FakeVault(secrets={})
    results = benchmark_all(vault, "default")
    assert results == []
