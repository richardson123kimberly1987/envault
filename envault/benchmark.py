"""Benchmark secret operations for performance profiling."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

BENCHMARK_OPERATIONS = ["encrypt", "decrypt", "hash", "export"]


class BenchmarkError(Exception):
    """Raised when a benchmark operation fails."""


@dataclass
class BenchmarkResult:
    operation: str
    iterations: int
    total_seconds: float
    min_seconds: float
    max_seconds: float
    avg_seconds: float
    secret_key: str = ""
    environment: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "iterations": self.iterations,
            "total_seconds": round(self.total_seconds, 6),
            "min_seconds": round(self.min_seconds, 6),
            "max_seconds": round(self.max_seconds, 6),
            "avg_seconds": round(self.avg_seconds, 6),
            "secret_key": self.secret_key,
            "environment": self.environment,
        }


def benchmark_secret(
    vault: Any,
    key: str,
    environment: str,
    operation: str = "encrypt",
    iterations: int = 100,
    passphrase: str = "",
) -> BenchmarkResult:
    """Benchmark a specific operation on a secret."""
    if operation not in BENCHMARK_OPERATIONS:
        raise BenchmarkError(
            f"Unknown operation '{operation}'. "
            f"Choose from: {', '.join(BENCHMARK_OPERATIONS)}"
        )
    if iterations < 1:
        raise BenchmarkError("iterations must be >= 1")

    entry = vault.get_secret(key, environment)
    if entry is None:
        raise BenchmarkError(f"Secret '{key}' not found in environment '{environment}'")

    from envault.crypto import encrypt, decrypt, derive_key

    pw = passphrase or "benchmark-passphrase"
    raw_value = entry.to_dict().get("value", "")

    timings: list[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        if operation == "encrypt":
            encrypt(raw_value, pw)
        elif operation == "decrypt":
            ciphertext = encrypt(raw_value, pw)
            decrypt(ciphertext, pw)
        elif operation == "hash":
            derive_key(pw, b"benchmarksalt00")
        elif operation == "export":
            entry.to_dict()
        timings.append(time.perf_counter() - t0)

    return BenchmarkResult(
        operation=operation,
        iterations=iterations,
        total_seconds=sum(timings),
        min_seconds=min(timings),
        max_seconds=max(timings),
        avg_seconds=sum(timings) / len(timings),
        secret_key=key,
        environment=environment,
    )


def benchmark_all(
    vault: Any,
    environment: str,
    operation: str = "encrypt",
    iterations: int = 50,
    passphrase: str = "",
) -> list[BenchmarkResult]:
    """Benchmark an operation across all secrets in an environment."""
    results = []
    for key in vault.list_secrets(environment):
        try:
            result = benchmark_secret(
                vault, key, environment, operation, iterations, passphrase
            )
            results.append(result)
        except BenchmarkError:
            continue
    return results
