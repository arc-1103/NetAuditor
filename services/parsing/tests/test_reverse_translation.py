from app.reverse_translation import compute_fidelity


def test_fidelity_is_perfect_for_identical_candidates():
    candidate = {
        "device": {"parsing_confidence": 0.9, "detected_vendor": "cisco"},
        "ssh": {"enabled": True, "version": "2"},
        "telnet": {"enabled": "DISABLED"},
    }
    assert compute_fidelity(candidate, candidate) == 1.0


def test_fidelity_is_trivially_perfect_when_nothing_was_extracted():
    """Nothing observable in the original chunk means there is nothing the
    round trip could lose."""
    original = {"schema_version": "1.0.0", "device": {"parsing_confidence": 0.2, "detected_vendor": "unknown"}}
    roundtrip = {"schema_version": "1.0.0", "device": {"parsing_confidence": 0.5, "detected_vendor": "cisco"}}
    assert compute_fidelity(original, roundtrip) == 1.0


def test_fidelity_is_zero_when_everything_vanishes_on_roundtrip():
    original = {
        "device": {"parsing_confidence": 0.9},
        "ssh": {"enabled": True, "version": "2"},
        "telnet": {"enabled": "DISABLED"},
    }
    roundtrip = {"device": {"parsing_confidence": 0.9}}
    assert compute_fidelity(original, roundtrip) == 0.0


def test_fidelity_is_partial_when_some_facts_survive():
    original = {
        "device": {"parsing_confidence": 0.9},
        "ssh": {"enabled": True, "version": "2"},
        "telnet": {"enabled": "DISABLED"},
    }
    roundtrip = {
        "device": {"parsing_confidence": 0.9},
        "ssh": {"enabled": True, "version": "2"},
    }
    fidelity = compute_fidelity(original, roundtrip)
    assert 0.0 < fidelity < 1.0


def test_device_identity_fields_are_excluded_from_the_diff():
    """config_sha256/parsing_confidence/detected_vendor come from
    device_context and the file hash, not from what Agent A read out of the
    chunk text — a mismatch there says nothing about extraction fidelity."""
    original = {
        "device": {
            "parsing_confidence": 0.91,
            "detected_vendor": "cisco",
            "config_sha256": "a" * 64,
        },
        "ssh": {"enabled": True, "version": "2"},
    }
    roundtrip = {
        "device": {
            "parsing_confidence": 0.42,
            "detected_vendor": "unknown",
            "config_sha256": "b" * 64,
        },
        "ssh": {"enabled": True, "version": "2"},
    }
    assert compute_fidelity(original, roundtrip) == 1.0


def test_list_order_does_not_affect_fidelity():
    original = {"logging": {"syslog_hosts": ["10.0.0.1", "10.0.0.2"]}}
    roundtrip = {"logging": {"syslog_hosts": ["10.0.0.2", "10.0.0.1"]}}
    assert compute_fidelity(original, roundtrip) == 1.0


def test_unknown_and_none_placeholders_are_not_facts():
    """SSHVersion.NONE ("none"), ProtocolStatus.UNKNOWN ("UNKNOWN") and their
    kin are "not observed" sentinels, not extracted facts — a round trip
    that doesn't reproduce them hasn't lost anything real."""
    original = {"ssh": {"version": "none"}, "telnet": {"enabled": "UNKNOWN"}, "snmp": {"version": "none"}}
    assert compute_fidelity(original, {}) == 1.0


def test_an_explicit_false_is_still_a_real_fact():
    """Unlike a placeholder, `enabled: false` is itself extracted
    information (e.g. "SSH explicitly disabled") and must be preserved."""
    original = {"ssh": {"enabled": False}}
    assert compute_fidelity(original, {}) == 0.0
    assert compute_fidelity(original, {"ssh": {"enabled": False}}) == 1.0
