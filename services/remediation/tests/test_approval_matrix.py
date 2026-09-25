"""Unit tests for app.approval_matrix — docs/Additional-Features.md §7."""

import pytest

from app.approval_matrix import ApprovalDenied, check_permission, dual_approval_satisfied


def test_operator_may_approve_low_risk_single_device_change():
    check_permission(role="operator", decision_action="SINGLE_APPROVAL", risk="LOW", blast_radius_count=0)


def test_operator_cannot_approve_high_risk_change():
    with pytest.raises(ApprovalDenied):
        check_permission(role="operator", decision_action="DUAL_APPROVAL", risk="HIGH", blast_radius_count=0)


def test_operator_cannot_approve_multi_device_change():
    with pytest.raises(ApprovalDenied):
        check_permission(role="operator", decision_action="SINGLE_APPROVAL", risk="LOW", blast_radius_count=2)


def test_admin_may_approve_medium_risk_multi_device_change():
    check_permission(role="admin", decision_action="SINGLE_APPROVAL", risk="MEDIUM", blast_radius_count=2)


def test_admin_may_approve_high_risk_change():
    check_permission(role="admin", decision_action="DUAL_APPROVAL", risk="HIGH", blast_radius_count=1)


def test_auditor_role_is_never_permitted():
    with pytest.raises(ApprovalDenied):
        check_permission(role="auditor", decision_action="SINGLE_APPROVAL", risk="LOW", blast_radius_count=0)


def test_block_classification_is_never_approvable_by_anyone():
    with pytest.raises(ApprovalDenied):
        check_permission(role="admin", decision_action="BLOCK", risk="LOW", blast_radius_count=0)


def test_dual_approval_requires_two_distinct_actors():
    assert dual_approval_satisfied("DUAL_APPROVAL", prior_approving_actors=set(), new_actor="admin-1") is False
    assert dual_approval_satisfied("DUAL_APPROVAL", prior_approving_actors={"admin-1"}, new_actor="admin-2") is True


def test_dual_approval_rejects_the_same_actor_approving_twice():
    """A second call from the same person must not satisfy the 2-person
    rule — it's meant to be two *independent* approvers."""
    result = dual_approval_satisfied("DUAL_APPROVAL", prior_approving_actors={"admin-1"}, new_actor="admin-1")
    assert result is False


def test_single_approval_tier_never_requires_a_second_approver():
    assert dual_approval_satisfied("SINGLE_APPROVAL", prior_approving_actors=set(), new_actor="operator-1") is True
