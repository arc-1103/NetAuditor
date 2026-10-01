from datetime import datetime, timedelta, timezone

import pytest

from app import waivers as w

NOW = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
KEY = w.device_key("Cisco", "Edge-RTR1")


def grant(waiver_id, control="CIS-NET-1.1.2", days=30, at=NOW - timedelta(days=1), key=KEY, actor="admin@x"):
    return {"id": waiver_id, "audit_run_id": "run-1", "control_id": control, "event_type": w.GRANTED, "actor": actor,
            "created_at": at.isoformat(), "payload": {"waiver_id": waiver_id, "device_key": key, "reason": "Isolated legacy system, mission 4417",
                                                      "expires_at": (NOW + timedelta(days=days)).isoformat(), "ticket": "CHG-88"}}


def revoke(waiver_id, at=NOW):
    return {"id": f"r-{waiver_id}", "audit_run_id": "run-1", "control_id": "CIS-NET-1.1.2", "event_type": w.REVOKED, "actor": "auditor-admin",
            "created_at": at.isoformat(), "payload": {"waiver_id": waiver_id, "reason": "system patched"}}


def test_device_identity_ignores_case_and_falls_back_to_the_config_hash():
    assert w.device_key("CISCO", "EDGE-rtr1") == w.device_key("cisco", "edge-RTR1") == "cisco|edge-rtr1"
    assert w.device_key("cisco", None, "abc") == "sha:abc"


def test_status_is_computed_from_events_and_the_clock():
    events = [grant("a", days=30), grant("b", days=-5, at=NOW - timedelta(days=40)), grant("c", days=30), revoke("c")]
    status = {x["waiver_id"]: x["status"] for x in w.evaluate(events, NOW)}
    assert status == {"a": "ACTIVE", "b": "EXPIRED", "c": "REVOKED"}
    revoked = next(x for x in w.evaluate(events, NOW) if x["waiver_id"] == "c")
    assert revoked["revoked_by"] == "auditor-admin" and revoked["revoked_reason"] == "system patched"


def test_a_waiver_expires_by_itself_as_time_passes():
    events = [grant("a", days=10)]
    assert w.evaluate(events, NOW)[0]["status"] == "ACTIVE"
    assert w.evaluate(events, NOW + timedelta(days=11))[0]["status"] == "EXPIRED"


def test_annotation_marks_only_the_waived_control_on_the_same_device():
    findings = [{"control_id": "CIS-NET-1.1.2", "severity": "CRITICAL"}, {"control_id": "CIS-NET-1.8.1", "severity": "MEDIUM"}]
    listing = w.evaluate([grant("a")], NOW)
    marked = w.annotate(findings, listing, KEY)
    assert marked[0]["waiver"]["granted_by"] == "admin@x" and marked[1]["waiver"] is None
    other = w.annotate(findings, listing, w.device_key("cisco", "other-rtr"))
    assert all(f["waiver"] is None for f in other)  # a waiver never leaks to another device
    counting, waived = w.split(marked)
    assert [f["control_id"] for f in counting] == ["CIS-NET-1.8.1"] and [f["control_id"] for f in waived] == ["CIS-NET-1.1.2"]


def test_a_lapsed_waiver_makes_the_finding_count_again_with_an_explanation():
    listing = w.evaluate([grant("a", days=-2, at=NOW - timedelta(days=30))], NOW)
    marked = w.annotate([{"control_id": "CIS-NET-1.1.2"}], listing, KEY)
    assert marked[0]["waiver"] is None and "expired" in marked[0]["waiver_note"]
    revoked = w.annotate([{"control_id": "CIS-NET-1.1.2"}], w.evaluate([grant("a"), revoke("a")], NOW), KEY)
    assert "revoked" in revoked[0]["waiver_note"]


def test_a_renewed_waiver_replaces_the_expired_one_with_no_stale_note():
    events = [grant("old", days=-2, at=NOW - timedelta(days=30)), grant("new", days=60)]
    marked = w.annotate([{"control_id": "CIS-NET-1.1.2"}], w.evaluate(events, NOW), KEY)
    assert marked[0]["waiver"]["waiver_id"] == "new" and "waiver_note" not in marked[0]


@pytest.mark.parametrize("reason,expires,message", [
    ("too short", NOW + timedelta(days=5), "justification"),
    (None, NOW + timedelta(days=5), "justification"),
    ("A sufficiently long written reason", NOW - timedelta(days=1), "future"),
    ("A sufficiently long written reason", NOW + timedelta(days=400), "at most"),
    ("A sufficiently long written reason", "not-a-date", "date/time"),
])
def test_invalid_grants_are_refused_with_a_clear_reason(reason, expires, message):
    with pytest.raises(w.WaiverError, match=message):
        w.validate_grant(reason, expires, NOW)


def test_valid_grant_returns_the_expiry_and_naive_times_are_treated_as_utc():
    assert w.validate_grant("A sufficiently long written reason", "2026-11-01T00:00:00", NOW) == datetime(2026, 11, 1, tzinfo=timezone.utc)
