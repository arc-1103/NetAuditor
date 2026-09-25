"""Unit tests for app.reachability_diff — docs/Additional-Features.md §4."""

from app.reachability_diff import diff_acl


def _entry(action, protocol="tcp", source="any", destination="10.0.0.0/24", port="443", sequence=10):
    return {"sequence": sequence, "action": action, "protocol": protocol, "source": source, "destination": destination, "port": port}


def test_no_change_reports_no_reachability_change():
    acl = {"ingress_entries": [_entry("permit")], "egress_entries": []}

    result = diff_acl(acl, acl)

    assert result["has_reachability_change"] is False
    assert result["acl_lines_touched"] == 0


def test_removing_a_permit_rule_is_a_newly_blocked_flow():
    before = {"ingress_entries": [_entry("permit")], "egress_entries": []}
    after = {"ingress_entries": [], "egress_entries": []}

    result = diff_acl(before, after)

    assert result["has_reachability_change"] is True
    assert len(result["ingress"]["newly_blocked_flows"]) == 1
    assert result["ingress"]["newly_permitted_flows"] == []


def test_adding_a_permit_rule_is_a_newly_permitted_flow():
    before = {"ingress_entries": [], "egress_entries": []}
    after = {"ingress_entries": [_entry("permit")], "egress_entries": []}

    result = diff_acl(before, after)

    assert len(result["ingress"]["newly_permitted_flows"]) == 1
    assert result["interfaces_touched"] == [{"side": "ingress", "acl_name": None}]


def test_flipping_permit_to_deny_for_the_same_flow_counts_as_a_line_touched_and_a_block():
    before = {"ingress_entries": [_entry("permit", sequence=10)], "egress_entries": []}
    after = {"ingress_entries": [_entry("deny", sequence=10)], "egress_entries": []}

    result = diff_acl(before, after)

    assert result["ingress"]["acl_lines_touched"] == 2  # old permit line gone, new deny line present
    assert len(result["ingress"]["newly_blocked_flows"]) == 1


def test_unrelated_deny_rule_change_does_not_affect_permitted_flows():
    before = {"ingress_entries": [_entry("deny", sequence=20, destination="10.0.0.99/32")], "egress_entries": []}
    after = {"ingress_entries": [], "egress_entries": []}

    result = diff_acl(before, after)

    assert result["ingress"]["newly_blocked_flows"] == []
    assert result["ingress"]["newly_permitted_flows"] == []
    assert result["ingress"]["acl_lines_touched"] == 1  # the deny line itself was still removed


def test_services_referenced_reflects_only_changed_flows():
    before = {"ingress_entries": [_entry("permit", port="22")], "egress_entries": []}
    after = {"ingress_entries": [_entry("permit", port="22"), _entry("permit", port="443", sequence=20)], "egress_entries": []}

    result = diff_acl(before, after)

    assert result["services_referenced"] == ["tcp/443"]


def test_egress_changes_are_tracked_independently_of_ingress():
    before = {"ingress_entries": [], "egress_entries": []}
    after = {"ingress_entries": [], "egress_entries": [_entry("permit")]}

    result = diff_acl(before, after)

    assert result["ingress"]["acl_lines_touched"] == 0
    assert result["egress"]["acl_lines_touched"] == 1
    assert result["interfaces_touched"] == [{"side": "egress", "acl_name": None}]
