"""
Mean-Time-to-Remediate & Compliance SLA — docs/Additional-Features.md §5.

A timestamp query against ledger_events, the same append-only table
Remediation and Compliance already write to — no new subsystem. Pairs each
control's first VIOLATION_DETECTED with its first later APPROVED; a
violation with no APPROVED yet is still open, and is flagged red once it's
outstripped its severity tier's SLA target.

docs/Additional-Features.md §5 names STIG-style CAT I/II/III tiers, but no
STIG bundle exists in this codebase yet (services/compliance/policies has
only the generic CIS Level-1 bundle) — CRITICAL/HIGH/MEDIUM+LOW stand in for
CAT I/II/III respectively, the same substitution risk_scorer.py's docstring
already makes for CIS Level 2 weight tiers.
"""

from collections import defaultdict
from datetime import datetime, timedelta, timezone

SLA_TARGETS = {
    "CRITICAL": timedelta(hours=8),
    "HIGH": timedelta(days=5),
    "MEDIUM": timedelta(days=30),
    "LOW": timedelta(days=30),
}
DEFAULT_SEVERITY = "MEDIUM"


def summarize_mttr(events: list[dict], *, now: datetime | None = None) -> dict:
    """events: ledger_events rows (audit_run_id, control_id, event_type,
    payload: dict, created_at: datetime), any order, VIOLATION_DETECTED and
    APPROVED only — see app/db.get_ledger_events."""
    now = now or datetime.now(timezone.utc)
    by_key: dict[tuple, list[dict]] = defaultdict(list)
    for event in events:
        by_key[(event["audit_run_id"], event["control_id"])].append(event)

    closed_durations: dict[str, list[timedelta]] = defaultdict(list)
    open_violations = []
    for (audit_run_id, control_id), key_events in by_key.items():
        key_events.sort(key=lambda e: e["created_at"])
        detected = next((e for e in key_events if e["event_type"] == "VIOLATION_DETECTED"), None)
        if detected is None:
            continue
        severity = str((detected.get("payload") or {}).get("severity") or DEFAULT_SEVERITY).upper()
        if severity not in SLA_TARGETS:
            severity = DEFAULT_SEVERITY
        approved = next(
            (e for e in key_events if e["event_type"] == "APPROVED" and e["created_at"] > detected["created_at"]),
            None,
        )
        if approved is not None:
            closed_durations[severity].append(approved["created_at"] - detected["created_at"])
        else:
            age = now - detected["created_at"]
            open_violations.append({
                "audit_run_id": audit_run_id,
                "control_id": control_id,
                "severity": severity,
                "age_seconds": age.total_seconds(),
                "over_sla": age > SLA_TARGETS[severity],
            })

    by_severity = {}
    for severity, target in SLA_TARGETS.items():
        durations = closed_durations.get(severity, [])
        avg_seconds = sum(d.total_seconds() for d in durations) / len(durations) if durations else None
        by_severity[severity] = {
            "avg_mttr_seconds": avg_seconds,
            "target_seconds": target.total_seconds(),
            "sample_size": len(durations),
        }

    return {
        "by_severity": by_severity,
        "open_violations": open_violations,
        "open_violations_over_sla": sum(1 for v in open_violations if v["over_sla"]),
    }
