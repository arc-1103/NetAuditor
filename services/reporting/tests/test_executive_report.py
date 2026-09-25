"""Unit tests for app.executive_report — docs/Additional-Features.md §6."""

from app import executive_report


def _finding(control_id, severity="LOW"):
    return {"control_id": control_id, "severity": severity}


def test_fleet_score_weights_by_control_count_not_by_averaging_percentages():
    big_device = [_finding("CIS-NET-1.6.1")]  # 1 of 11 controls
    small_device = [_finding("ONLY-CONTROL", "CRITICAL")]  # 1 of 1 control

    result = executive_report.fleet_score({"run-a": big_device, "run-b": small_device})

    assert result["devices_scored"] == 2
    assert result["fleet_score"] > 50  # dominated by the 11-control device, not a 50/50 average


def test_fleet_score_trend_is_one_point_per_evaluation_in_order():
    evaluations = [
        {"audit_run_id": "run-a", "evaluated_at": "2026-01-01T00:00:00Z", "findings_snapshot": []},
        {"audit_run_id": "run-a", "evaluated_at": "2026-01-02T00:00:00Z", "findings_snapshot": [_finding("CIS-NET-1.1.2", "CRITICAL")]},
    ]

    points = executive_report.fleet_score_trend(evaluations)

    assert [p["evaluated_at"] for p in points] == ["2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"]
    assert points[0]["fleet_score"] == 100
    assert points[1]["fleet_score"] < 100


def test_top_exposed_devices_ranks_worst_compliance_score_first():
    findings_by_run = {
        "run-clean": [],
        "run-bad": [_finding("CIS-NET-1.1.2", "CRITICAL")],
    }

    result = executive_report.top_exposed_devices(findings_by_run, {}, limit=5)

    assert result[0]["audit_run_id"] == "run-bad"
    assert result[0]["compliance_score"] < result[1]["compliance_score"]


def test_top_exposed_devices_respects_limit():
    findings_by_run = {f"run-{i}": [] for i in range(10)}

    result = executive_report.top_exposed_devices(findings_by_run, {}, limit=5)

    assert len(result) == 5


def test_violations_found_and_resolved_derives_resolved_from_absence():
    ledger_events = [
        {"audit_run_id": "run-a", "control_id": "CIS-NET-1.1.2", "event_type": "VIOLATION_DETECTED"},
        {"audit_run_id": "run-a", "control_id": "CIS-NET-1.6.1", "event_type": "VIOLATION_DETECTED"},
    ]
    # CIS-NET-1.1.2 no longer appears in current findings (fixed); 1.6.1 still does.
    current_findings_by_run = {"run-a": [_finding("CIS-NET-1.6.1")]}

    result = executive_report.violations_found_and_resolved(ledger_events, current_findings_by_run)

    assert result == {"found": 2, "resolved": 1, "still_open": 1}


def test_remediation_action_mix_classifies_by_outcome_not_only_decision_label():
    proposals = [
        {"approval_status": "APPROVED", "decision_action": "AUTO_APPLY", "applied_at": "2026-01-01T00:00:00Z", "preflight_status": "SAFE"},
        {"approval_status": "APPROVED", "decision_action": "SINGLE_APPROVAL", "applied_at": None, "preflight_status": "SAFE"},
        {"approval_status": "REJECTED", "decision_action": "DUAL_APPROVAL", "applied_at": None, "preflight_status": "SAFE"},
        {"approval_status": "PENDING", "decision_action": "BLOCK", "applied_at": None, "preflight_status": "RISK_FLAGS"},
    ]

    result = executive_report.remediation_action_mix(proposals)

    assert result["total"] == 4
    assert result["auto_applied"] == 1
    assert result["human_approved"] == 1
    assert result["rejected"] == 1
    assert result["blocked"] == 1
    assert result["pending"] == 1


def test_remediation_action_mix_of_no_proposals_is_all_zero():
    result = executive_report.remediation_action_mix([])

    assert result == {"total": 0, "auto_applied": 0, "human_approved": 0, "blocked": 0, "rejected": 0, "pending": 0}
