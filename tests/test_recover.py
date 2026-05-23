"""Tests for envault.recover module."""
import pytest
from envault.recover import RecoverError, RecoverResult, recover_secret


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _snap(env: str, name: str, value: str) -> dict:
    return {"secrets": {env: {name: value}}}


def _chk(env: str, name: str, value: str) -> dict:
    return {"secrets": {env: {name: value}}}


def _hist(env: str, name: str, value: str) -> dict:
    return {"environment": env, "secret_name": name, "value": value}


# ---------------------------------------------------------------------------
# RecoverResult.to_dict
# ---------------------------------------------------------------------------

def test_recover_result_to_dict():
    r = RecoverResult(
        secret_name="DB_PASS",
        environment="prod",
        recovered_value="s3cr3t",
        source="snapshot",
        success=True,
    )
    d = r.to_dict()
    assert d["secret_name"] == "DB_PASS"
    assert d["environment"] == "prod"
    assert d["recovered_value"] == "s3cr3t"
    assert d["source"] == "snapshot"
    assert d["success"] is True


# ---------------------------------------------------------------------------
# recover_secret – snapshot source
# ---------------------------------------------------------------------------

def test_recover_from_snapshot():
    snaps = [_snap("prod", "API_KEY", "abc123")]
    result = recover_secret(None, "prod", "API_KEY", snapshots=snaps)
    assert result.success is True
    assert result.source == "snapshot"
    assert result.recovered_value == "abc123"


def test_recover_uses_latest_snapshot():
    snaps = [
        _snap("prod", "API_KEY", "old_value"),
        _snap("prod", "API_KEY", "new_value"),
    ]
    result = recover_secret(None, "prod", "API_KEY", snapshots=snaps)
    assert result.recovered_value == "new_value"


# ---------------------------------------------------------------------------
# recover_secret – checkpoint source
# ---------------------------------------------------------------------------

def test_recover_from_checkpoint_when_no_snapshot():
    chks = [_chk("staging", "DB_URL", "postgres://localhost")]
    result = recover_secret(None, "staging", "DB_URL", checkpoints=chks)
    assert result.success is True
    assert result.source == "checkpoint"
    assert result.recovered_value == "postgres://localhost"


def test_snapshot_preferred_over_checkpoint():
    snaps = [_snap("prod", "TOKEN", "from_snap")]
    chks = [_chk("prod", "TOKEN", "from_chk")]
    result = recover_secret(None, "prod", "TOKEN", snapshots=snaps, checkpoints=chks)
    assert result.source == "snapshot"
    assert result.recovered_value == "from_snap"


# ---------------------------------------------------------------------------
# recover_secret – history source
# ---------------------------------------------------------------------------

def test_recover_from_history():
    hist = [_hist("dev", "SECRET", "hist_val")]
    result = recover_secret(None, "dev", "SECRET", history=hist)
    assert result.success is True
    assert result.source == "history"
    assert result.recovered_value == "hist_val"


def test_checkpoint_preferred_over_history():
    chks = [_chk("dev", "X", "from_chk")]
    hist = [_hist("dev", "X", "from_hist")]
    result = recover_secret(None, "dev", "X", checkpoints=chks, history=hist)
    assert result.source == "checkpoint"


# ---------------------------------------------------------------------------
# recover_secret – not found
# ---------------------------------------------------------------------------

def test_recover_returns_failure_when_not_found():
    result = recover_secret(None, "prod", "MISSING")
    assert result.success is False
    assert result.source == "none"
    assert result.recovered_value is None


def test_recover_returns_failure_with_empty_sources():
    result = recover_secret(None, "prod", "KEY", snapshots=[], checkpoints=[], history=[])
    assert result.success is False


def test_recover_skips_wrong_environment_in_history():
    hist = [_hist("staging", "KEY", "val")]
    result = recover_secret(None, "prod", "KEY", history=hist)
    assert result.success is False
