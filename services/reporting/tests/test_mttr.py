"""Unit tests for app.mttr — docs/Additional-Features.md §5."""

from datetime import datetime, timedelta, timezone

from app import mttr

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _event(event_type, control_id, when, severity=None, audit_run_id="run-1"):
    return {
        "audit_run_id": audit_run_id,
        "control_id": control_id,
        "event_type": event_type,
        "payload": {"severity": severity} if severity else {},
        "created_at": when,
    }


def test_computes_mttr_between_detection_and_approval():
    events = [
        _event("VIOLATION_DETECTED", "CIS-NET-1.1.2", NOW, severity="CRITICAL"),
        _event("APPROVED", "CIS-NET-1.1.2", NOW + timedelta(hours=2)),
    ]

    result = mttr.summarize_mttr(events, now=NOW + timedelta(days=1))

    critical = result["by_severity"]["CRITICAL"]
    assert critical["sample_size"] == 1
    assert critical["avg_mttr_seconds"] == timedelta(hours=2).total_seconds()


def test_open_violation_past_its_sla_target_is_flagged():
    events = [_event("VIOLATION_DETECTED", "CIS-NET-1.1.2", NOW, severity="CRITICAL")]

    result = mttr.summarize_mttr(events, now=NOW + timedelta(hours=9))  # target is 8h

    assert result["open_violations_over_sla"] == 1
    assert result["open_violations"][0]["over_sla"] is True


def test_open_violation_within_its_sla_target_is_not_flagged():
    events = [_event("VIOLATION_DETECTED", "CIS-NET-1.1.2", NOW, severity="CRITICAL")]

    result = mttr.summarize_mttr(events, now=NOW + timedelta(hours=1))

    assert result["open_violations_over_sla"] == 0


def test_unrecognized_severity_falls_back_to_the_default_tier():
    events = [_event("VIOLATION_DETECTED", "CIS-NET-1.1.2", NOW, severity="WEIRD")]

    result = mttr.summarize_mttr(events, now=NOW)

    assert result["open_violations"][0]["severity"] == mttr.DEFAULT_SEVERITY


def test_approved_event_before_detection_is_ignored_not_negative():
    """A stale APPROVED from a previous evaluation cycle for the same
    control must never produce a negative MTTR."""
    events = [
        _event("APPROVED", "CIS-NET-1.1.2", NOW),
        _event("VIOLATION_DETECTED", "CIS-NET-1.1.2", NOW + timedelta(hours=1), severity="LOW"),
    ]

    result = mttr.summarize_mttr(events, now=NOW + timedelta(days=1))

    assert result["by_severity"]["LOW"]["sample_size"] == 0
    assert len(result["open_violations"]) == 1


def test_each_severity_tier_reports_its_own_sla_target():
    result = mttr.summarize_mttr([], now=NOW)

    assert result["by_severity"]["CRITICAL"]["target_seconds"] == timedelta(hours=8).total_seconds()
    assert result["by_severity"]["HIGH"]["target_seconds"] == timedelta(days=5).total_seconds()
    assert result["by_severity"]["MEDIUM"]["target_seconds"] == timedelta(days=30).total_seconds()
