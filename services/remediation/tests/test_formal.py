import ipaddress

from app import formal
from app.formal import Flow, Line

net = ipaddress.ip_network
ANY = net("0.0.0.0/0")
OPERATORS = net("192.168.50.0/24")
DEVICE = net("10.0.0.1/32")

SSH_FROM_OPERATORS = Flow("tcp", OPERATORS, DEVICE, formal.EPHEMERAL, (22, 22))
BGP_INBOUND = Flow("tcp", net("10.0.0.2/32"), DEVICE, formal.EPHEMERAL, (179, 179))
TELNET_FROM_ANYWHERE = Flow("tcp", ANY, DEVICE, None, (23, 23))


def acl(*lines):
    return list(lines)


def permit(proto, src, dst, sport=None, dport=None, standard=False):
    return Line("permit", Flow(proto, net(src), net(dst), sport, dport), standard)


def deny_all():
    return Line("deny", Flow("ip", ANY, ANY))


def test_acl_covering_the_whole_subnet_is_proven_not_sampled():
    lines = acl(permit("tcp", "192.168.50.0/24", "0.0.0.0/0", None, (22, 22)), deny_all())
    assert formal.verify_permitted(lines, SSH_FROM_OPERATORS) == {"status": "PROVEN", "counterexample": None}


def test_half_a_subnet_fails_with_a_concrete_counterexample_outside_the_half():
    # A check of only the first host (192.168.50.1) would pass; the proof does not.
    lines = acl(permit("tcp", "192.168.50.0/25", "0.0.0.0/0", None, (22, 22)), deny_all())
    result = formal.verify_permitted(lines, SSH_FROM_OPERATORS)
    assert result["status"] == "COUNTEREXAMPLE"
    cex = result["counterexample"]
    assert ipaddress.ip_address(cex["src"]) in net("192.168.50.128/25") and cex["dport"] == 22 and cex["proto"] == "tcp"


def test_first_match_order_and_implicit_deny_are_modelled():
    deny_first = acl(Line("deny", Flow("tcp", ANY, ANY, None, (22, 22))), permit("ip", "0.0.0.0/0", "0.0.0.0/0"))
    assert formal.verify_permitted(deny_first, SSH_FROM_OPERATORS)["status"] == "COUNTEREXAMPLE"
    permit_first = acl(permit("ip", "0.0.0.0/0", "0.0.0.0/0"), Line("deny", Flow("tcp", ANY, ANY, None, (22, 22))))
    assert formal.verify_permitted(permit_first, SSH_FROM_OPERATORS)["status"] == "PROVEN"
    assert formal.verify_permitted([], SSH_FROM_OPERATORS)["status"] == "COUNTEREXAMPLE"  # implicit deny


def test_standard_acl_matches_on_source_only():
    lines = acl(permit("ip", "192.168.50.0/24", "0.0.0.0/0", standard=True), deny_all())
    assert formal.verify_permitted(lines, SSH_FROM_OPERATORS)["status"] == "PROVEN"


def test_cegis_repairs_an_acl_that_forgot_bgp_and_the_result_is_proven():
    broken = acl(permit("tcp", "192.168.50.0/24", "0.0.0.0/0", None, (22, 22)), deny_all())
    outcome = formal.cegis_repair(broken, [SSH_FROM_OPERATORS, BGP_INBOUND], [TELNET_FROM_ANYWHERE])
    assert outcome["status"] == "REPAIRED" and outcome["rounds"] == 1
    assert outcome["added"] == ["permit tcp host 10.0.0.2 range 1024 65535 host 10.0.0.1 eq 179"]
    assert outcome["trace"][0]["inserted_at"] == 2  # before the deny that blocked it
    for flow in (SSH_FROM_OPERATORS, BGP_INBOUND):
        assert formal.verify_permitted(outcome["lines"], flow)["status"] == "PROVEN"
    assert formal.verify_permitted(outcome["lines"], TELNET_FROM_ANYWHERE)["status"] == "COUNTEREXAMPLE"  # still blocked


def test_already_safe_acl_is_left_alone():
    good = acl(permit("tcp", "192.168.50.0/24", "0.0.0.0/0", None, (22, 22)), deny_all())
    outcome = formal.cegis_repair(good, [SSH_FROM_OPERATORS], [])
    assert outcome["status"] == "ALREADY_SAFE" and outcome["added"] == [] and outcome["rounds"] == 0


def test_a_repair_that_would_break_a_must_block_rule_is_refused_not_applied():
    everything_ssh = Flow("tcp", ANY, DEVICE, formal.EPHEMERAL, (22, 22))
    must_block = Flow("tcp", net("203.0.113.0/24"), DEVICE, None, (22, 22))
    outcome = formal.cegis_repair(acl(deny_all()), [everything_ssh], [must_block])
    assert outcome["status"] == "UNREPAIRABLE" and outcome["added"] == [] and "must stay blocked" in outcome["reason"]


def test_ios_formatting_round_trips_through_common_shapes():
    assert formal.to_ios(permit("tcp", "10.0.0.2/32", "10.0.0.1/32", None, (179, 179))) == "permit tcp host 10.0.0.2 host 10.0.0.1 eq 179"
    assert formal.to_ios(permit("ip", "0.0.0.0/0", "0.0.0.0/0")) == "permit ip any any"
    assert formal.to_ios(permit("ip", "10.0.0.0/24", "0.0.0.0/0", standard=True)) == "permit 10.0.0.0 0.0.0.255"
