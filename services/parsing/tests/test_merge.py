import hashlib

from app.merge import merge_baselines
from app.models import DeviceContext
from schema.security_baseline import SecurityBaseline


def baseline(vendor="cisco", confidence=0.9, **kwargs):
    return SecurityBaseline(
        device={
            "detected_vendor": vendor,
            "config_sha256": hashlib.sha256(b"config").hexdigest(),
            "parsing_confidence": confidence,
            **kwargs,
        }
    )


def test_lists_merge_without_duplicates():
    a = baseline()
    b = SecurityBaseline(
        device={
            "detected_vendor": "cisco",
            "config_sha256": hashlib.sha256(b"config").hexdigest(),
            "parsing_confidence": 0.9,
        },
        ssh={"allowed_ciphers": ["AES128"]},
    )
    merged, conflicts = merge_baselines([a, b])
    assert merged.ssh.allowed_ciphers == ["AES128"]
    assert conflicts == []


def test_known_value_beats_unknown():
    a = SecurityBaseline(
        device={
            "detected_vendor": "cisco",
            "config_sha256": hashlib.sha256(b"config").hexdigest(),
            "parsing_confidence": 0.9,
        },
        telnet={"enabled": "UNKNOWN"},
    )
    b = SecurityBaseline(
        device={
            "detected_vendor": "cisco",
            "config_sha256": hashlib.sha256(b"config").hexdigest(),
            "parsing_confidence": 0.9,
        },
        telnet={"enabled": "DISABLED"},
    )
    merged, _ = merge_baselines([a, b])
    assert merged.telnet.enabled == "DISABLED"


def test_scalar_conflict_is_deterministic():
    a = baseline(raw_hostname="first")
    b = baseline(raw_hostname="other")
    merged, conflicts = merge_baselines([a, b])
    assert merged.device.raw_hostname == "first"
    assert "device.raw_hostname" in conflicts


def test_device_identity_is_forced_by_job_context():
    a = baseline(vendor="unknown")
    b = baseline(vendor="unknown")
    context = DeviceContext("cisco", "IOS-XE", "17.9.3", "EDGE-RTR", None, 0.97)
    merged, _ = merge_baselines([a, b], device_context=context)
    assert merged.device.detected_vendor == "cisco"
    assert merged.device.detected_os == "IOS-XE"


def test_unknown_helper_accepts_unhashable_values():
    from app.merge import _is_unknown
    assert _is_unknown({"key": "value"}) is False
    assert _is_unknown(["value"]) is False


def test_explicit_chunk_values_do_not_get_erased_by_model_defaults():
    first = baseline()
    second = SecurityBaseline(
        device={
            "detected_vendor": "cisco",
            "config_sha256": hashlib.sha256(b"config").hexdigest(),
            "parsing_confidence": 0.9,
        },
        ssh={"enabled": True, "version": "2"},
    )
    merged, conflicts = merge_baselines([first, second])
    assert merged.ssh.enabled is True
    assert merged.ssh.version == "2"
    assert conflicts == []


def _baseline_with_telnet(enabled: str) -> SecurityBaseline:
    return SecurityBaseline(
        device={
            "detected_vendor": "cisco",
            "config_sha256": hashlib.sha256(b"config").hexdigest(),
            "parsing_confidence": 0.9,
        },
        telnet={"enabled": enabled},
    )


def test_a_later_chunks_risky_finding_survives_an_earlier_safe_observation():
    """An earlier chunk's "DISABLED" must not hide a later chunk's
    "ENABLED" for the same field just because it was processed first —
    the real device fact is that telnet is enabled somewhere."""
    safe_first = _baseline_with_telnet("DISABLED")
    risky_second = _baseline_with_telnet("ENABLED")
    merged, conflicts = merge_baselines([safe_first, risky_second])
    assert merged.telnet.enabled == "ENABLED"
    assert "telnet.enabled" in conflicts


def test_a_risky_finding_survives_regardless_of_chunk_order():
    risky_first = _baseline_with_telnet("ENABLED")
    safe_second = _baseline_with_telnet("DISABLED")
    merged, conflicts = merge_baselines([risky_first, safe_second])
    assert merged.telnet.enabled == "ENABLED"
    assert "telnet.enabled" in conflicts


def test_non_boolean_scalar_conflict_still_keeps_the_first_observation():
    """Two different hostnames aren't a safe/risky pair — the existing
    keep-first policy is unchanged for genuinely different scalars."""
    a = baseline(raw_hostname="first")
    b = baseline(raw_hostname="other")
    merged, conflicts = merge_baselines([a, b])
    assert merged.device.raw_hostname == "first"
    assert "device.raw_hostname" in conflicts
