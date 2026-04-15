"""Tests for envault.diff module."""

import pytest

from envault.diff import DiffError, SecretDiff, diff_environments, format_diff


# ---------------------------------------------------------------------------
# Helpers / fakes
# ---------------------------------------------------------------------------

class _FakeVault:
    """Minimal vault stub for diff tests."""

    def __init__(self, data: dict):
        # data = {env_name: {key: value}}
        self._data = data

    def list_environments(self):
        return list(self._data.keys())

    def list_secrets(self, env: str):
        return dict(self._data.get(env, {}))


# ---------------------------------------------------------------------------
# SecretDiff.to_dict
# ---------------------------------------------------------------------------

def test_secret_diff_to_dict():
    d = SecretDiff(key="FOO", status="added", left_value=None, right_value="bar")
    result = d.to_dict()
    assert result["key"] == "FOO"
    assert result["status"] == "added"
    assert result["right_value"] == "bar"


# ---------------------------------------------------------------------------
# diff_environments
# ---------------------------------------------------------------------------

@pytest.fixture()
def vault():
    return _FakeVault({
        "staging": {"DB_URL": "postgres://staging", "SECRET_KEY": "abc", "ONLY_STAGING": "yes"},
        "production": {"DB_URL": "postgres://prod", "SECRET_KEY": "abc", "ONLY_PROD": "no"},
    })


def test_diff_raises_for_missing_left_env(vault):
    with pytest.raises(DiffError, match="'missing'"):
        diff_environments(vault, "missing", "production")


def test_diff_raises_for_missing_right_env(vault):
    with pytest.raises(DiffError, match="'nope'"):
        diff_environments(vault, "staging", "nope")


def test_diff_returns_correct_statuses(vault):
    diffs = diff_environments(vault, "staging", "production")
    by_key = {d.key: d for d in diffs}

    assert by_key["DB_URL"].status == "changed"
    assert by_key["SECRET_KEY"].status == "unchanged"
    assert by_key["ONLY_STAGING"].status == "removed"
    assert by_key["ONLY_PROD"].status == "added"


def test_diff_results_sorted_by_key(vault):
    diffs = diff_environments(vault, "staging", "production")
    keys = [d.key for d in diffs]
    assert keys == sorted(keys)


def test_diff_hides_values_by_default(vault):
    diffs = diff_environments(vault, "staging", "production")
    for d in diffs:
        assert d.left_value is None
        assert d.right_value is None


def test_diff_shows_values_when_requested(vault):
    diffs = diff_environments(vault, "staging", "production", show_values=True)
    by_key = {d.key: d for d in diffs}
    assert by_key["DB_URL"].left_value == "postgres://staging"
    assert by_key["DB_URL"].right_value == "postgres://prod"


# ---------------------------------------------------------------------------
# format_diff
# ---------------------------------------------------------------------------

def test_format_diff_empty():
    assert format_diff([]) == "No differences found."


def test_format_diff_symbols():
    diffs = [
        SecretDiff(key="A", status="added"),
        SecretDiff(key="B", status="removed"),
        SecretDiff(key="C", status="changed"),
        SecretDiff(key="D", status="unchanged"),
    ]
    output = format_diff(diffs)
    assert output.startswith("+")
    assert "- B" in output
    assert "~ C" in output
    assert "  D" in output


def test_format_diff_shows_values_for_changed():
    diffs = [
        SecretDiff(key="X", status="changed", left_value="old", right_value="new"),
    ]
    output = format_diff(diffs, show_values=True)
    assert "'old'" in output
    assert "'new'" in output
