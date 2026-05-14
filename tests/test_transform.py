"""Tests for envault.transform."""

from __future__ import annotations

import base64
from typing import Any

import pytest

from envault.transform import (
    TRANSFORM_OPS,
    TransformError,
    TransformResult,
    transform_secret,
)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str) -> None:
        self._value = value
        self._updated: str | None = None

    def decrypt(self, passphrase: str) -> str:  # noqa: ARG002
        return self._value

    def update_value(self, new_value: str, passphrase: str) -> None:  # noqa: ARG002
        self._updated = new_value

    def to_dict(self) -> dict[str, Any]:
        return {"value": self._value}


class _FakeVault:
    def __init__(self, entries: dict[tuple[str, str], _FakeEntry]) -> None:
        self._entries = entries
        self.saved = False

    def get_secret(self, environment: str, secret: str) -> _FakeEntry | None:
        return self._entries.get((environment, secret))

    def save(self) -> None:
        self.saved = True


PASS = "hunter2"


def _vault_with(env: str, key: str, value: str) -> _FakeVault:
    return _FakeVault({(env, key): _FakeEntry(value)})


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_transform_ops_constant_not_empty() -> None:
    assert len(TRANSFORM_OPS) > 0


def test_transform_result_to_dict() -> None:
    r = TransformResult("k", "dev", "uppercase", "hello", "HELLO")
    d = r.to_dict()
    assert d["secret"] == "k"
    assert d["operation"] == "uppercase"
    assert d["original"] == "hello"
    assert d["transformed"] == "HELLO"


def test_uppercase() -> None:
    vault = _vault_with("dev", "KEY", "hello world")
    result = transform_secret(vault, "dev", "KEY", "uppercase", PASS)
    assert result.transformed == "HELLO WORLD"
    assert vault.saved


def test_lowercase() -> None:
    vault = _vault_with("dev", "KEY", "HELLO")
    result = transform_secret(vault, "dev", "KEY", "lowercase", PASS)
    assert result.transformed == "hello"


def test_strip() -> None:
    vault = _vault_with("dev", "KEY", "  padded  ")
    result = transform_secret(vault, "dev", "KEY", "strip", PASS)
    assert result.transformed == "padded"


def test_reverse() -> None:
    vault = _vault_with("dev", "KEY", "abc")
    result = transform_secret(vault, "dev", "KEY", "reverse", PASS)
    assert result.transformed == "cba"


def test_base64encode() -> None:
    vault = _vault_with("dev", "KEY", "secret")
    result = transform_secret(vault, "dev", "KEY", "base64encode", PASS)
    assert result.transformed == base64.b64encode(b"secret").decode()


def test_base64decode() -> None:
    encoded = base64.b64encode(b"decoded").decode()
    vault = _vault_with("dev", "KEY", encoded)
    result = transform_secret(vault, "dev", "KEY", "base64decode", PASS)
    assert result.transformed == "decoded"


def test_base64decode_invalid_raises() -> None:
    vault = _vault_with("dev", "KEY", "not-valid-base64!!!")
    with pytest.raises(TransformError, match="base64decode failed"):
        transform_secret(vault, "dev", "KEY", "base64decode", PASS)


def test_unknown_operation_raises() -> None:
    vault = _vault_with("dev", "KEY", "value")
    with pytest.raises(TransformError, match="Unknown operation"):
        transform_secret(vault, "dev", "KEY", "explode", PASS)


def test_missing_secret_raises() -> None:
    vault = _FakeVault({})
    with pytest.raises(TransformError, match="not found"):
        transform_secret(vault, "dev", "MISSING", "uppercase", PASS)
