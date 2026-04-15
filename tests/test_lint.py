"""Tests for envault.lint module."""
import pytest
from envault.lint import LintIssue, LintResult, LintError, lint_secrets, LINT_CHECKS


class _FakeEntry:
    def __init__(self, value: str):
        self._value = value

    def to_dict(self):
        return {"value": self._value}


class _FakeVault:
    def __init__(self, data: dict):
        # data = {env: {key: value}}
        self._data = data

    def list_environments(self):
        return list(self._data.keys())

    def list_secrets(self, env):
        return list(self._data.get(env, {}).keys())

    def get_secret(self, env, key):
        val = self._data.get(env, {}).get(key)
        return _FakeEntry(val) if val is not None else None


def test_lint_checks_constant_not_empty():
    assert len(LINT_CHECKS) > 0


def test_lint_issue_to_dict():
    issue = LintIssue("MY_KEY", "prod", "weak_value", "weak")
    d = issue.to_dict()
    assert d["key"] == "MY_KEY"
    assert d["environment"] == "prod"
    assert d["check"] == "weak_value"
    assert d["message"] == "weak"


def test_lint_result_passed_when_no_issues():
    result = LintResult()
    assert result.passed is True
    assert result.to_dict()["passed"] is True
    assert result.to_dict()["issue_count"] == 0


def test_lint_result_failed_when_issues_present():
    result = LintResult(issues=[LintIssue("K", "dev", "empty_value", "msg")])
    assert result.passed is False
    assert result.to_dict()["issue_count"] == 1


def test_lint_empty_value_detected():
    vault = _FakeVault({"dev": {"MY_KEY": ""}})
    result = lint_secrets(vault)
    checks = [i.check for i in result.issues]
    assert "empty_value" in checks


def test_lint_weak_value_detected():
    vault = _FakeVault({"dev": {"DB_PASS": "password"}})
    result = lint_secrets(vault)
    checks = [i.check for i in result.issues]
    assert "weak_value" in checks


def test_lint_naming_convention_detected():
    vault = _FakeVault({"dev": {"mySecret": "somevalue"}})
    result = lint_secrets(vault)
    checks = [i.check for i in result.issues]
    assert "naming_convention" in checks


def test_lint_valid_secret_passes():
    vault = _FakeVault({"prod": {"API_KEY": "xK92!mPqR#7z"}})
    result = lint_secrets(vault)
    assert result.passed is True


def test_lint_specific_environment():
    vault = _FakeVault({"dev": {"BAD": "password"}, "prod": {"API_KEY": "strongvalue!"}})
    result = lint_secrets(vault, environment="prod")
    assert result.passed is True


def test_lint_raises_when_no_environments():
    vault = _FakeVault({})
    with pytest.raises(LintError):
        lint_secrets(vault)


def test_lint_multiple_issues_same_secret():
    vault = _FakeVault({"dev": {"badkey": "password"}})
    result = lint_secrets(vault)
    checks = {i.check for i in result.issues}
    assert "weak_value" in checks
    assert "naming_convention" in checks


def test_lint_issue_environment_recorded_correctly():
    """Ensure each issue records the environment it was found in."""
    vault = _FakeVault({"staging": {"MY_KEY": ""}, "prod": {"API_KEY": "xK92!mPqR#7z"}})
    result = lint_secrets(vault)
    for issue in result.issues:
        assert issue.environment == "staging"
