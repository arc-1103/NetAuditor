from app.reachability_fallback import estimate_reachability_impact


def test_no_signal_for_a_script_with_no_acl_or_route_lines():
    est = estimate_reachability_impact("configure terminal\nip ssh version 2\nend\nwrite memory")

    assert est.to_dict() == {
        "newly_blocked": [], "newly_permitted": [], "routing_statements_touched": [], "blast_radius": [],
    }


def test_applying_a_new_access_class_is_narrowing_not_widening():
    """ios_ssh_mgmt_acl_fix.j2's own shape: defines a brand-new ACL, then
    applies it via access-class in the same script. The ACL's own permit/deny
    lines must NOT be classified (the ACL has no effect until applied) —
    only the access-class line itself carries the narrowing signal."""
    script = (
        "ip access-list standard NETAUDIT-MGMT\n"
        " permit 10.0.0.0 0.0.0.255\n"
        " deny any log\n"
        "exit\n"
        "line vty 0 15\n"
        " access-class NETAUDIT-MGMT in\n"
        " transport input ssh\n"
        "end\n"
    )

    est = estimate_reachability_impact(script)

    assert est.newly_permitted == []
    assert any("access-class NETAUDIT-MGMT applied" in f for f in est.newly_blocked)
    assert set(est.blast_radius) == {"NETAUDIT-MGMT", "vty 0 15"}


def test_removing_an_access_class_is_widening():
    est = estimate_reachability_impact("line vty 0 15\n no access-class NETAUDIT-MGMT in\nend")

    assert any("removed" in f for f in est.newly_permitted)
    assert est.newly_blocked == []


def test_transport_input_none_is_newly_blocked():
    est = estimate_reachability_impact("line vty 0 4\n transport input none\nend")

    assert any("transport input none" in f for f in est.newly_blocked)


def test_transport_input_replaced_with_a_value_has_no_claimed_direction():
    """Cannot tell narrowing from widening without the prior allowed set —
    ios_disable_telnet.j2 sets `transport input ssh` to REMOVE telnet, so
    guessing "widening" here would be actively wrong, not just imprecise."""
    est = estimate_reachability_impact("line vty 0 15\n transport input ssh\nend")

    assert est.newly_blocked == []
    assert est.newly_permitted == []


def test_removing_an_acl_permit_entry_is_narrowing():
    script = "ip access-list standard MGMT\n no permit 10.0.0.0 0.0.0.255\nexit"

    est = estimate_reachability_impact(script)

    assert any("removes 'permit" in f for f in est.newly_blocked)


def test_removing_an_acl_deny_entry_is_widening():
    script = "ip access-list standard MGMT\n no deny any log\nexit"

    est = estimate_reachability_impact(script)

    assert any("removes 'deny" in f for f in est.newly_permitted)


def test_adding_an_acl_entry_is_not_classified():
    """Could be a brand-new ACL not yet applied anywhere — see the
    NETAUDIT-MGMT case above. Adding is only ever "touched," never scored."""
    script = "ip access-list extended TEST\n permit tcp any any eq 22\nexit"

    est = estimate_reachability_impact(script)

    assert est.newly_blocked == []
    assert est.newly_permitted == []
    assert est.touched_acl_names == ["TEST"]


def test_numbered_acl_removal_of_a_deny_is_widening():
    est = estimate_reachability_impact("no access-list 101 deny ip any any")

    assert any("access-list 101" in f for f in est.newly_permitted)


def test_fortinet_trusthost_is_narrowing():
    est = estimate_reachability_impact('config system admin\n edit "admin"\n  set trusthost1 10.0.0.0 255.255.255.0\n next\nend')

    assert any("trusted host" in f for f in est.newly_blocked)


def test_fortinet_allowaccess_has_no_claimed_direction():
    est = estimate_reachability_impact("config system interface\n edit \"mgmt\"\n  set allowaccess https ssh ping\n next\nend")

    assert est.newly_blocked == []
    assert est.newly_permitted == []


def test_route_statements_are_touched_but_not_classified():
    """Multi-hop/BGP/OSPF impact is explicitly out of scope — see module
    docstring; a routing change is visible for blast-radius purposes only."""
    est = estimate_reachability_impact("router bgp 65000\n no neighbor 10.1.1.1 remote-as 65001\nend")

    assert est.routing_statements_touched == ["router bgp 65000", "no neighbor 10.1.1.1 remote-as 65001"]
    assert est.newly_blocked == []
    assert est.newly_permitted == []
