from app.fix_simulation import apply_fix


def test_fix_sets_passing_state_without_mutating_the_original():
    base = {"telnet": {"enabled": "ENABLED"}, "snmp": {"community_strings": ["public", "corp-ro"]}}
    fixed = apply_fix(base, "CIS-NET-1.1.2")
    assert fixed["telnet"]["enabled"] == "DISABLED"
    assert base["telnet"]["enabled"] == "ENABLED"
    assert apply_fix(base, "CIS-NET-1.2.2")["snmp"]["community_strings"] == ["corp-ro"]


def test_unknown_control_has_no_simulation():
    assert apply_fix({}, "CIS-NOPE-9") is None
