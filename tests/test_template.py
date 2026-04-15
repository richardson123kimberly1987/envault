"""Tests for envault.template."""
from __future__ import annotations

import pytest

from envault.template import TemplateError, RenderResult, render_template


# ---------------------------------------------------------------------------
# Minimal fakes
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, value: str):
        self.value = value

    def to_dict(self):
        return {"value": self.value}


class _FakeVault:
    def __init__(self, secrets: dict[tuple[str, str], str]):
        self._secrets = secrets

    def get_secret(self, environment: str, key: str):
        v = self._secrets.get((environment, key))
        return _FakeEntry(v) if v is not None else None


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_render_result_to_dict():
    r = RenderResult(rendered="hello", resolved=["A"], missing=["B"])
    d = r.to_dict()
    assert d["rendered"] == "hello"
    assert d["resolved"] == ["A"]
    assert d["missing"] == ["B"]


def test_render_simple_substitution():
    vault = _FakeVault({("prod", "DB_PASS"): "s3cr3t"})
    result = render_template("password={{ DB_PASS }}", vault, "prod")
    assert result.rendered == "password=s3cr3t"
    assert "DB_PASS" in result.resolved
    assert result.missing == []


def test_render_multiple_placeholders():
    vault = _FakeVault({("dev", "HOST"): "localhost", ("dev", "PORT"): "5432"})
    result = render_template("{{ HOST }}:{{ PORT }}", vault, "dev")
    assert result.rendered == "localhost:5432"
    assert set(result.resolved) == {"HOST", "PORT"}


def test_render_uses_default_when_missing():
    vault = _FakeVault({})
    result = render_template("val={{ MISSING:fallback }}", vault, "prod")
    assert result.rendered == "val=fallback"
    assert "MISSING" in result.missing


def test_render_leaves_placeholder_when_no_default_non_strict():
    vault = _FakeVault({})
    result = render_template("val={{ UNKNOWN }}", vault, "prod", strict=False)
    assert "{{ UNKNOWN }}" in result.rendered
    assert "UNKNOWN" in result.missing


def test_render_strict_raises_on_missing():
    vault = _FakeVault({})
    with pytest.raises(TemplateError, match="UNKNOWN"):
        render_template("val={{ UNKNOWN }}", vault, "prod", strict=True)


def test_render_strict_ok_when_default_provided():
    vault = _FakeVault({})
    result = render_template("val={{ MISSING:ok }}", vault, "prod", strict=True)
    assert result.rendered == "val=ok"


def test_render_empty_template():
    vault = _FakeVault({})
    result = render_template("", vault, "prod")
    assert result.rendered == ""
    assert result.resolved == []
    assert result.missing == []


def test_render_no_placeholders():
    vault = _FakeVault({})
    result = render_template("plain text", vault, "prod")
    assert result.rendered == "plain text"
