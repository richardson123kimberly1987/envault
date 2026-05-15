"""Tests for envault.squeeze."""
from __future__ import annotations

from typing import Dict, List, Optional

import pytest

from envault.squeeze import SqueezeError, SqueezeResult, squeeze_environment, _is_blank


# ---------------------------------------------------------------------------
# Fake helpers
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str):
        self._value = value

    def decrypt(self) -> str:
        return self._value

    def to_dict(self) -> dict:
        return {"value": self._value}


class _FakeVault:
    def __init__(self, envs: Dict[str, Dict[str, str]]):
        self._envs: Dict[str, Dict[str, _FakeEntry]] = {
            env: {k: _FakeEntry(v) for k, v in secrets.items()}
            for env, secrets in envs.items()
        }
        self.saved = False

    def list_secrets(self, environment: str) -> Optional[List[str]]:
        if environment not in self._envs:
            return None
        return list(self._envs[environment].keys())

    def get_secret(self, environment: str, name: str) -> Optional[_FakeEntry]:
        return self._envs.get(environment, {}).get(name)

    def delete_secret(self, environment: str, name: str) -> None:
        self._envs[environment].pop(name, None)

    def save(self) -> None:
        self.saved = True


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------

def test_is_blank_empty_string():
    assert _is_blank("") is True


def test_is_blank_whitespace_only():
    assert _is_blank("   ") is True
    assert _is_blank("\t\n") is True


def test_is_blank_non_empty():
    assert _is_blank("hello") is False
    assert _is_blank(" x ") is False


def test_squeeze_result_to_dict():
    r = SqueezeResult(environment="prod", removed=["A"], kept=3, dry_run=False)
    d = r.to_dict()
    assert d["environment"] == "prod"
    assert d["removed"] == ["A"]
    assert d["kept"] == 3
    assert d["dry_run"] is False


def test_squeeze_removes_blank_secrets():
    vault = _FakeVault({"dev": {"KEY": "value", "BLANK": "", "SPACE": "  "}})
    result = squeeze_environment(vault, "dev")
    assert set(result.removed) == {"BLANK", "SPACE"}
    assert result.kept == 1
    assert vault.saved is True


def test_squeeze_dry_run_does_not_mutate():
    vault = _FakeVault({"dev": {"KEY": "value", "BLANK": ""}})
    result = squeeze_environment(vault, "dev", dry_run=True)
    assert result.removed == ["BLANK"]
    assert result.dry_run is True
    # vault must not be mutated
    assert vault.list_secrets("dev") == ["KEY", "BLANK"]
    assert vault.saved is False


def test_squeeze_no_blanks_keeps_all():
    vault = _FakeVault({"prod": {"A": "x", "B": "y"}})
    result = squeeze_environment(vault, "prod")
    assert result.removed == []
    assert result.kept == 2
    assert vault.saved is False  # nothing to save


def test_squeeze_missing_environment_raises():
    vault = _FakeVault({})
    with pytest.raises(SqueezeError, match="not found"):
        squeeze_environment(vault, "missing")


def test_squeeze_decrypt_error_raises():
    class _BadEntry:
        def decrypt(self):
            raise RuntimeError("crypto failure")
        def to_dict(self):
            return {}

    vault = _FakeVault({})
    vault._envs["qa"] = {"SECRET": _BadEntry()}  # type: ignore[assignment]
    with pytest.raises(SqueezeError, match="crypto failure"):
        squeeze_environment(vault, "qa")
