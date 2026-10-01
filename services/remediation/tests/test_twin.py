import ipaddress

from app import twin

BASELINE = {
    "topology": {
        "interfaces": [
            {"name": "GigabitEthernet0/1", "ip_address": "10.0.0.1", "subnet_mask": "255.255.255.252"},
            {"name": "GigabitEthernet0/2", "ip_address": "10.9.0.1", "subnet_mask": "255.255.255.0"},
        ],
        "routing_neighbors": [
            {"protocol": "bgp", "neighbor_ip": "10.0.0.2", "remote_asn": 65002},
            {"protocol": "ospf", "neighbor_ip": "10.9.0.2"},
        ],
    }
}
MGMT = [ipaddress.ip_network("192.168.50.0/24")]

FORGETS_BGP = """
ip access-list extended EDGE-IN
 permit tcp 192.168.50.0 0.0.0.255 any eq 22
 deny ip any any log
exit
interface GigabitEthernet0/1
 ip access-group EDGE-IN in
"""

KEEPS_BGP = """
ip access-list extended EDGE-IN
 permit tcp host 10.0.0.2 any eq bgp
 permit tcp host 10.0.0.2 eq bgp any
 permit tcp 192.168.50.0 0.0.0.255 any eq 22
 deny ip any any log
exit
interface GigabitEthernet0/1
 ip access-group EDGE-IN in
"""

MGMT_ACL_ONLY = """
ip access-list standard NETAUDIT-MGMT
 permit 10.0.0.0 0.0.0.255
 deny any log
exit
line vty 0 15
 access-class NETAUDIT-MGMT in
"""


def results(script, protected=MGMT):
    outcome = twin.simulate(script, BASELINE, protected)
    return outcome, {c["description"].split(" (")[0]: c["result"] for c in outcome["checks"]}


def test_an_acl_that_forgets_bgp_is_caught_with_the_session_named():
    outcome, by_check = results(FORGETS_BGP)
    assert outcome["modeled"] and outcome["broken"] == 1
    assert by_check["BGP session with 10.0.0.2 on GigabitEthernet0/1"] == "BROKEN"
    assert twin.risk_flags(outcome) == ["Digital twin: would break — BGP session with 10.0.0.2 on GigabitEthernet0/1 (ACL EDGE-IN in)"]


def test_an_acl_that_keeps_bgp_and_management_is_preserved():
    outcome, by_check = results(KEEPS_BGP)
    assert outcome["broken"] == 0 and set(by_check.values()) == {"PRESERVED"}
    assert any("SSH from protected subnet 192.168.50.0/24" in d for d in by_check)


def test_ospf_on_another_interface_is_not_touched_by_an_acl_on_gi0_1():
    _, by_check = results(FORGETS_BGP)
    assert not any("OSPF" in d for d in by_check)


def test_management_acl_that_locks_out_a_protected_subnet_is_caught():
    outcome, by_check = results(MGMT_ACL_ONLY)  # permits 10.0.0.0/24 only; operators sit in 192.168.50.0/24
    assert by_check["SSH from protected subnet 192.168.50.0/24 via vty 0 15"] == "BROKEN"
    assert outcome["broken"] == 1
    fixed = MGMT_ACL_ONLY.replace("permit 10.0.0.0 0.0.0.255", "permit 192.168.50.0 0.0.0.255")
    assert results(fixed)[0]["broken"] == 0


def test_implicit_deny_and_first_match_order_are_respected():
    entries = twin.parse_script("ip access-list extended A\n deny tcp any any eq 22\n permit ip any any\n").acls["A"]
    assert twin.permits(entries, "tcp", "1.1.1.1", "2.2.2.2", 40000, 22) is False
    assert twin.permits(entries, "tcp", "1.1.1.1", "2.2.2.2", 40000, 80) is True
    assert twin.permits([], "tcp", "1.1.1.1", "2.2.2.2", 1, 1) is False


def test_unmodeled_dialect_or_missing_baseline_is_never_reported_as_safe():
    forti = "config system interface\n edit mgmt\n set allowaccess https ssh\nend\n"
    outcome = twin.simulate(forti, BASELINE, MGMT)
    assert outcome["modeled"] is False and outcome["broken"] == 0 and "not add or attach ACLs" in outcome["note"]
    assert twin.simulate(FORGETS_BGP, None, MGMT)["modeled"] is False


def test_numbered_acl_and_wildcard_matching():
    script = "access-list 101 permit tcp 10.0.0.0 0.0.0.255 any eq 179\ninterface GigabitEthernet0/1\n ip access-group 101 in\n"
    outcome, by_check = results(script, protected=[])
    assert by_check["BGP session with 10.0.0.2 on GigabitEthernet0/1"] == "BROKEN"  # return leg (sport 179) not permitted by dport rule


HALF_SUBNET_MGMT = """
ip access-list standard NETAUDIT-MGMT
 permit 192.168.50.0 0.0.0.127
 deny any log
exit
line vty 0 15
 access-class NETAUDIT-MGMT in
"""


def test_z3_catches_a_partial_subnet_that_sampling_one_host_would_miss():
    outcome = twin.simulate(HALF_SUBNET_MGMT, BASELINE, MGMT)
    check = outcome["checks"][0]
    assert outcome["method"] == "z3-smt" and check["method"] == "z3-smt"
    assert check["result"] == "BROKEN"  # 192.168.50.0/25 permitted, but the subnet is /24
    assert ipaddress.ip_address(check["counterexample"]["src"]) in ipaddress.ip_network("192.168.50.128/25")
    assert check["counterexample"]["dport"] == 22


def test_a_broken_acl_comes_with_a_synthesised_repair_that_is_then_proven():
    outcome = twin.simulate(FORGETS_BGP, BASELINE, MGMT)
    repair = outcome["repairs"][0]
    assert repair["status"] == "REPAIRED" and repair["acl"] == "EDGE-IN"
    assert any("host 10.0.0.2" in line and "eq 179" in line for line in repair["add_lines"])
    assert repair["rounds"] >= 1


def test_a_clean_change_has_no_repairs():
    outcome = twin.simulate(KEEPS_BGP, BASELINE, MGMT)
    assert outcome["broken"] == 0 and outcome["repairs"] == []


def test_without_z3_the_twin_falls_back_and_says_it_only_sampled(monkeypatch):
    monkeypatch.setattr(twin, "formal", None)
    outcome = twin.simulate(FORGETS_BGP, BASELINE, MGMT)
    assert outcome["method"] == "sample-packet" and outcome["broken"] == 1
    assert all(c["method"] == "sample-packet" for c in outcome["checks"]) and outcome["repairs"] == []
