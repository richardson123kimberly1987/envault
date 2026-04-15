"""Tests for envault.access module."""

import pytest

from envault.access import (
    ACCESS_ROLES,
    AccessError,
    AccessPolicy,
    AccessRule,
)


# ---------------------------------------------------------------------------
# AccessRule
# ---------------------------------------------------------------------------

def test_access_roles_constant_not_empty():
    assert len(ACCESS_ROLES) >= 3


def test_access_rule_valid():
    rule = AccessRule(identity="alice", role="read")
    assert rule.identity == "alice"
    assert rule.role == "read"
    assert rule.environment is None


def test_access_rule_invalid_role_raises():
    with pytest.raises(AccessError, match="Invalid role"):
        AccessRule(identity="alice", role="superuser")


def test_access_rule_to_dict():
    rule = AccessRule(identity="bob", role="write", environment="production")
    d = rule.to_dict()
    assert d == {"identity": "bob", "role": "write", "environment": "production"}


def test_access_rule_from_dict_round_trip():
    original = AccessRule(identity="carol", role="admin", environment="staging")
    restored = AccessRule.from_dict(original.to_dict())
    assert restored.identity == original.identity
    assert restored.role == original.role
    assert restored.environment == original.environment


# ---------------------------------------------------------------------------
# AccessPolicy
# ---------------------------------------------------------------------------

@pytest.fixture()
def policy() -> AccessPolicy:
    return AccessPolicy()


def test_add_rule_returns_rule(policy):
    rule = policy.add_rule("alice", "read")
    assert isinstance(rule, AccessRule)
    assert len(policy.rules) == 1


def test_add_rule_replaces_existing(policy):
    policy.add_rule("alice", "read")
    policy.add_rule("alice", "write")
    assert len(policy.rules) == 1
    assert policy.rules[0].role == "write"


def test_remove_rule_returns_true_when_removed(policy):
    policy.add_rule("alice", "read")
    assert policy.remove_rule("alice") is True
    assert len(policy.rules) == 0


def test_remove_rule_returns_false_when_not_found(policy):
    assert policy.remove_rule("nobody") is False


def test_get_role_returns_most_permissive(policy):
    policy.add_rule("alice", "read")           # global read
    policy.add_rule("alice", "write", "prod")  # write in prod
    assert policy.get_role("alice", "prod") == "write"
    assert policy.get_role("alice", "dev") == "read"


def test_get_role_unknown_identity_returns_none(policy):
    assert policy.get_role("ghost") is None


def test_can_returns_true_for_sufficient_role(policy):
    policy.add_rule("alice", "admin")
    assert policy.can("alice", "read") is True
    assert policy.can("alice", "write") is True
    assert policy.can("alice", "admin") is True


def test_can_returns_false_for_insufficient_role(policy):
    policy.add_rule("bob", "read")
    assert policy.can("bob", "write") is False


def test_can_unknown_action_raises(policy):
    with pytest.raises(AccessError, match="Unknown action"):
        policy.can("alice", "delete")


def test_policy_round_trip(policy):
    policy.add_rule("alice", "admin")
    policy.add_rule("bob", "read", "staging")
    restored = AccessPolicy.from_dict(policy.to_dict())
    assert len(restored.rules) == 2
    assert restored.can("alice", "admin") is True
    assert restored.get_role("bob", "staging") == "read"
