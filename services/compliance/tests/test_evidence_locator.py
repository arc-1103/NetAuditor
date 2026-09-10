from app.evidence_locator import attach, locate


def test_locates_sanitized_cisco_evidence_by_one_based_line():
    source = "hostname edge\nip ssh version 1\ntransport input telnet ssh"
    assert locate("CIS-NET-1.1.1", source) == [{"line": 2, "text": "ip ssh version 1"}]
    assert locate("CIS-NET-1.1.2", source) == [{"line": 3, "text": "transport input telnet ssh"}]


def test_unknown_control_and_missing_source_are_explicitly_empty():
    assert locate("UNKNOWN", "anything") == []
    assert attach([{"control_id": "CIS-NET-1.1.1"}], None)[0]["source_lines"] == []
