"""Unit tests for app.counterfactual — docs/Suggestions.md item 3."""

from app.counterfactual import counterfactual


def _finding(control_id, severity="HIGH"):
    return {"control_id": control_id, "severity": severity}


def _acl(entries):
    return {"ingress_entries": entries, "egress_entries": []}


def _permit(port="443"):
    return {"sequence": 10, "action": "permit", "protocol": "tcp", "source": "any", "destination": "10.0.0.0/24", "port": port}


def test_fewer_violations_and_no_reachability_change_is_safe():
    result = counterfactual(
        current_findings=[_finding("CIS-NET-1.1.2", "CRITICAL")],
        proposed_findings=[],
        current_acl=None, proposed_acl=None,
    )

    assert result["verdict"] == "SAFE"
    assert result["compliance_delta"] > 0
    assert result["violations_resolved"] == ["CIS-NET-1.1.2"]
    assert result["violations_introduced"] == []


def test_regressed_compliance_is_a_risk_flag():
    result = counterfactual(
        current_findings=[],
        proposed_findings=[_finding("CIS-NET-1.1.2", "CRITICAL")],
        current_acl=None, proposed_acl=None,
    )

    assert result["verdict"] == "RISK_FLAG"
    assert result["compliance_delta"] < 0
    assert result["violations_introduced"] == ["CIS-NET-1.1.2"]


def test_opening_new_access_is_a_risk_flag_even_if_compliance_improves():
    """docs/Suggestions.md's own point: an improved score alone doesn't make
    a change SAFE if it also newly permits a flow that wasn't allowed before."""
    result = counterfactual(
        current_findings=[_finding("CIS-NET-1.1.2", "CRITICAL")],
        proposed_findings=[],
        current_acl=_acl([]), proposed_acl=_acl([_permit()]),
    )

    assert result["compliance_delta"] > 0
    assert result["verdict"] == "RISK_FLAG"
    assert result["reachability"]["ingress"]["newly_permitted_flows"]


def test_tightening_access_alongside_fewer_violations_is_safe():
    result = counterfactual(
        current_findings=[_finding("CIS-NET-1.1.2", "CRITICAL")],
        proposed_findings=[],
        current_acl=_acl([_permit()]), proposed_acl=_acl([]),
    )

    assert result["verdict"] == "SAFE"
    assert result["reachability"]["ingress"]["newly_blocked_flows"]


def test_no_acl_supplied_means_no_reachability_analysis():
    result = counterfactual(current_findings=[], proposed_findings=[], current_acl=None, proposed_acl=None)

    assert result["reachability"] is None


def test_identical_baselines_are_safe_with_zero_delta():
    finding = _finding("CIS-NET-1.1.2", "CRITICAL")
    result = counterfactual([finding], [finding], None, None)

    assert result["verdict"] == "SAFE"
    assert result["compliance_delta"] == 0
    assert result["violations_resolved"] == []
    assert result["violations_introduced"] == []
