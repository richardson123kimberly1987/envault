"""Tests for envault.pipeline."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest

from envault.pipeline import (
    PipelineError,
    PipelineResult,
    PipelineStep,
    run_pipeline,
    run_pipeline_all,
)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str) -> None:
        self._value = value

    def to_dict(self) -> Dict[str, Any]:
        return {"value": self._value}


class _FakeVault:
    def __init__(self, secrets: Dict[str, str]) -> None:
        self._secrets: Dict[str, str] = dict(secrets)
        self.saved = False

    def get_secret(self, env: str, key: str) -> Optional[_FakeEntry]:
        v = self._secrets.get(key)
        return _FakeEntry(v) if v is not None else None

    def set_secret(self, env: str, key: str, value: str) -> None:
        self._secrets[key] = value

    def list_secrets(self, env: str) -> List[str]:
        return list(self._secrets.keys())

    def save(self) -> None:
        self.saved = True


# ---------------------------------------------------------------------------
# PipelineStep
# ---------------------------------------------------------------------------

def test_step_applies_transform():
    step = PipelineStep("upper", str.upper)
    assert step.apply("hello") == "HELLO"


def test_step_raises_pipeline_error_on_failure():
    def boom(v: str) -> str:
        raise ValueError("oops")

    step = PipelineStep("boom", boom)
    with pytest.raises(PipelineError, match="boom"):
        step.apply("x")


# ---------------------------------------------------------------------------
# PipelineResult
# ---------------------------------------------------------------------------

def test_pipeline_result_to_dict():
    r = PipelineResult(key="K", environment="prod", original="a", final="B", steps_applied=["s1"])
    d = r.to_dict()
    assert d["key"] == "K"
    assert d["original"] == "a"
    assert d["final"] == "B"
    assert d["steps_applied"] == ["s1"]
    assert d["skipped"] is False


# ---------------------------------------------------------------------------
# run_pipeline
# ---------------------------------------------------------------------------

def test_run_pipeline_transforms_value():
    vault = _FakeVault({"DB_PASS": "secret"})
    steps = [PipelineStep("upper", str.upper), PipelineStep("strip", str.strip)]
    result = run_pipeline(vault, "prod", "DB_PASS", steps)
    assert result.final == "SECRET"
    assert result.steps_applied == ["upper", "strip"]
    assert vault._secrets["DB_PASS"] == "SECRET"
    assert vault.saved is True


def test_run_pipeline_dry_run_does_not_save():
    vault = _FakeVault({"KEY": "value"})
    steps = [PipelineStep("upper", str.upper)]
    result = run_pipeline(vault, "dev", "KEY", steps, dry_run=True)
    assert result.final == "VALUE"
    assert vault._secrets["KEY"] == "value"  # unchanged
    assert vault.saved is False


def test_run_pipeline_missing_key_raises():
    vault = _FakeVault({})
    with pytest.raises(PipelineError, match="not found"):
        run_pipeline(vault, "prod", "MISSING", [])


def test_run_pipeline_no_steps_returns_original():
    vault = _FakeVault({"X": "abc"})
    result = run_pipeline(vault, "prod", "X", [])
    assert result.final == "abc"
    assert result.steps_applied == []


# ---------------------------------------------------------------------------
# run_pipeline_all
# ---------------------------------------------------------------------------

def test_run_pipeline_all_processes_all_keys():
    vault = _FakeVault({"A": "hello", "B": "world"})
    steps = [PipelineStep("upper", str.upper)]
    results = run_pipeline_all(vault, "staging", steps)
    assert len(results) == 2
    finals = {r.key: r.final for r in results}
    assert finals["A"] == "HELLO"
    assert finals["B"] == "WORLD"


def test_run_pipeline_all_dry_run():
    vault = _FakeVault({"X": "x", "Y": "y"})
    steps = [PipelineStep("upper", str.upper)]
    run_pipeline_all(vault, "prod", steps, dry_run=True)
    assert vault.saved is False
    assert vault._secrets["X"] == "x"
