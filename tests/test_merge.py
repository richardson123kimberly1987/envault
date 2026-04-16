import pytest
from envault.merge import merge_environments, MergeError, MergeResult


class _FakeEntry:
    def __init__(self, value):
        self.value = value
        self._data = {"value": value, "version": 1}

    def to_dict(self):
        return dict(self._data)


class _FakeVault:
    def __init__(self, data):
        # data: {env: {key: value_str}}
        self._data = {
            env: {k: _FakeEntry(v) for k, v in secrets.items()}
            for env, secrets in data.items()
        }
        self._saved = []

    def list_environments(self):
        return list(self._data.keys())

    def list_secrets(self, env):
        return list(self._data.get(env, {}).keys())

    def get_secret(self, env, key):
        return self._data.get(env, {}).get(key)

    def set_secret(self, env, key, value):
        if env not in self._data:
            self._data[env] = {}
        self._data[env][key] = _FakeEntry(value)

    def save(self):
        self._saved.append(True)


def test_merge_result_to_dict():
    r = MergeResult("a", "b", merged=1, skipped=0, conflicts=0, details={"X": "merged"})
    d = r.to_dict()
    assert d["source"] == "a"
    assert d["merged"] == 1
    assert d["details"]["X"] == "merged"


def test_merge_copies_missing_keys():
    vault = _FakeVault({"staging": {"A": "val_a", "B": "val_b"}, "production": {}})
    result = merge_environments(vault, "staging", "production", strategy="keep")
    assert result.merged == 2
    assert vault.get_secret("production", "A").value == "val_a"


def test_merge_keep_strategy_preserves_existing():
    vault = _FakeVault(
        {"staging": {"A": "new"}, "production": {"A": "old"}}
    )
    result = merge_environments(vault, "staging", "production", strategy="keep")
    assert vault.get_secret("production", "A").value == "old"
    assert result.skipped == 1
    assert result.conflicts == 1


def test_merge_overwrite_strategy_replaces_existing():
    vault = _FakeVault(
        {"staging": {"A": "new"}, "production": {"A": "old"}}
    )
    result = merge_environments(vault, "staging", "production", strategy="overwrite")
    assert vault.get_secret("production", "A").value == "new"
    assert result.merged == 1
    assert result.conflicts == 1


def test_merge_skip_strategy_skips_all_conflicts():
    vault = _FakeVault(
        {"staging": {"A": "x", "B": "y"}, "production": {"A": "old"}}
    )
    result = merge_environments(vault, "staging", "production", strategy="skip")
    assert result.skipped >= 1


def test_merge_missing_source_raises():
    vault = _FakeVault({"production": {}})
    with pytest.raises(MergeError, match="source"):
        merge_environments(vault, "staging", "production")


def test_merge_same_env_raises():
    vault = _FakeVault({"staging": {"A": "v"}})
    with pytest.raises(MergeError):
        merge_environments(vault, "staging", "staging")
