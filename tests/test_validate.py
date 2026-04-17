"""Tests for envault.validate."""
import pytest
from envault.validate import (
    validate_secrets, ValidateError, ValidationResult, ValidationIssue, VALIDATE_RULES
)


class _FakeEntry:
    def __init__(self, value: str):
        self._value = value

    def to_dict(self):
        return {"value": self._value}


class _FakeVault:
    def __init__(self, secrets: dict):
        self._secrets = secrets

    def list_secrets(self, env):
        return list(self._secrets.get(env, {}).keys())

    def get_secret(self, env, key):
        return self._secrets.get(env, {}).get(key)


@pytest.fixture
def vault():
    return _FakeVault({
        "prod": {
            "DB_PASS": _FakeEntry("s3cr3t"),
            "API_KEY": _FakeEntry("abc 123"),
            "EMPTY": _FakeEntry(""),
        }
    })


def test_validate_rules_constant_not_empty():
    assert len(VALIDATE_RULES) > 0


def test_passes_with_no_rules(vault):
    result = validate_secrets(vault, "prod", not_empty=False)
    assert isinstance(result, ValidationResult)
    assert result.passed


def test_not_empty_catches_blank(vault):
    result = validate_secrets(vault, "prod", not_empty=True)
    assert not result.passed
    keys = [i.key for i in result.issues]
    assert "EMPTY" in keys


def test_min_length_violation(vault):
    result = validate_secrets(vault, "prod", min_length=10, not_empty=False)
    assert not result.passed
    rules = [i.rule for i in result.issues]
    assert "min_length" in rules


def test_max_length_violation(vault):
    result = validate_secrets(vault, "prod", max_length=3, not_empty=False)
    assert not result.passed
    rules = [i.rule for i in result.issues]
    assert "max_length" in rules


def test_no_spaces_violation(vault):
    result = validate_secrets(vault, "prod", no_spaces=True, not_empty=False)
    assert not result.passed
    space_issues = [i for i in result.issues if i.rule == "no_spaces"]
    assert any(i.key == "API_KEY" for i in space_issues)


def test_regex_violation(vault):
    result = validate_secrets(vault, "prod", regex=r"^\d+$", not_empty=False)
    assert not result.passed
    regex_issues = [i for i in result.issues if i.rule == "regex"]
    assert len(regex_issues) > 0


def test_invalid_regex_raises(vault):
    with pytest.raises(ValidateError):
        validate_secrets(vault, "prod", regex="[invalid")


def test_to_dict_structure(vault):
    result = validate_secrets(vault, "prod", not_empty=True)
    d = result.to_dict()
    assert "passed" in d
    assert "issues" in d
    assert isinstance(d["issues"], list)


def test_issue_to_dict():
    issue = ValidationIssue("KEY", "prod", "not_empty", "msg")
    d = issue.to_dict()
    assert d["key"] == "KEY"
    assert d["environment"] == "prod"
    assert d["rule"] == "not_empty"


def test_empty_environment_passes(vault):
    result = validate_secrets(vault, "staging", not_empty=True)
    assert result.passed
