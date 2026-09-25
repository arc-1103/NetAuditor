"""
Executive Compliance Report — docs/Additional-Features.md §6.

Composes data this service (and the ledger) already has into the artifact a
non-technical stakeholder can read: fleet score + trend, top-5 exposure,
violations found/resolved, remediation action mix, MTTR by tier, and a
per-finding provenance chain. Deliberately built on Sections 1 and 5 rather
than a new subsystem, exactly as the doc specifies.
"""

from app.scoring import CONTROL_WEIGHTS, summarize
from app.scoring import weight as _weight


def fleet_score(findings_by_run: dict[str, list[dict]]) -> dict:
    """Same "not an average of device percentages" rule as
    services/compliance/app/risk_scorer.fleet_score — duplicated here for
    the same reason CONTROL_CATALOG is (see pdf_service.py's docstring)."""
    total_weight = 0
    total_passed_weight = 0
    for findings in findings_by_run.values():
        failed = {f["control_id"]: _weight(f) for f in findings if f.get("control_id")}
        universe = dict(CONTROL_WEIGHTS)
        for control_id, weight in failed.items():
            universe.setdefault(control_id, weight)
        total_weight += sum(universe.values())
        total_passed_weight += sum(w for cid, w in universe.items() if cid not in failed)
    return {
        "devices_scored": len(findings_by_run),
        "fleet_score": round((total_passed_weight / total_weight) * 100) if total_weight else 100,
    }


def fleet_score_trend(evaluations: list[dict]) -> list[dict]:
    """evaluations: audit_evaluations rows (evaluated_at, findings_snapshot:
    list[dict]), any order, across every run — audit_evaluations is
    append-only (unlike compliance_findings, which is replaced on
    re-evaluation), so this is the only place a historical trend can come
    from. One point per evaluated_at timestamp actually recorded — this
    service doesn't resample onto a fixed calendar grid."""
    by_run_latest_before: dict[str, list[dict]] = {}
    points = []
    for evaluation in sorted(evaluations, key=lambda e: e["evaluated_at"]):
        by_run_latest_before[evaluation["audit_run_id"]] = evaluation["findings_snapshot"]
        score = fleet_score(dict(by_run_latest_before))
        points.append({"evaluated_at": evaluation["evaluated_at"], "fleet_score": score["fleet_score"]})
    return points


def top_exposed_devices(findings_by_run: dict[str, list[dict]], run_metadata: dict[str, dict], limit: int = 5) -> list[dict]:
    """run_metadata: {audit_run_id: {"original_filename"|"detected_vendor"|...}}
    for display — this module stays free of any device-identity assumption
    beyond "one audit_run_id is one device instance" (see
    services/compliance/app/db.get_findings_by_run's docstring)."""
    scored = []
    for audit_run_id, findings in findings_by_run.items():
        summary = summarize(findings)
        scored.append({
            "audit_run_id": audit_run_id,
            **run_metadata.get(audit_run_id, {}),
            "compliance_score": summary["compliance_score"],
            "total_findings": summary["total_findings"],
            "risk_score": summary["risk_score"],
        })
    scored.sort(key=lambda d: (d["compliance_score"], -d["risk_score"]))
    return scored[:limit]


def violations_found_and_resolved(ledger_events: list[dict], current_findings_by_run: dict[str, list[dict]]) -> dict:
    """"Found" = VIOLATION_DETECTED events in the window. "Resolved" = a
    (run, control) pair that had a VIOLATION_DETECTED but whose control_id
    is no longer present in that run's *current* findings — there's no
    separate "RESOLVED" ledger event type (nothing writes one; a control
    simply stops appearing once it passes, see compliance_findings' own
    "a control that passed is simply absent"), so this is derived rather
    than counted directly."""
    detected = [e for e in ledger_events if e["event_type"] == "VIOLATION_DETECTED"]
    still_open = {
        (audit_run_id, f["control_id"])
        for audit_run_id, findings in current_findings_by_run.items()
        for f in findings
        if f.get("control_id")
    }
    resolved = sum(1 for e in detected if (e["audit_run_id"], e["control_id"]) not in still_open)
    return {"found": len(detected), "resolved": resolved, "still_open": len(detected) - resolved}


def remediation_action_mix(proposals: list[dict]) -> dict:
    """proposals: remediation_proposals rows across every run. Splits by
    what actually happened (approval_status) rather than only the decision
    table's advisory classification (decision_action), since AUTO_APPLY is
    advisory-only today (see services/remediation/app/decision.py) — a
    proposal classified AUTO_APPLY that a human still had to click through
    is reported as human-approved, not auto-applied."""
    auto_applied = sum(1 for p in proposals if p.get("applied_at") and p.get("decision_action") == "AUTO_APPLY")
    human_approved = sum(1 for p in proposals if p.get("approval_status") == "APPROVED" and not (p.get("applied_at") and p.get("decision_action") == "AUTO_APPLY"))
    blocked = sum(1 for p in proposals if p.get("decision_action") == "BLOCK" or p.get("preflight_status") != "SAFE")
    rejected = sum(1 for p in proposals if p.get("approval_status") == "REJECTED")
    return {
        "total": len(proposals),
        "auto_applied": auto_applied,
        "human_approved": human_approved,
        "blocked": blocked,
        "rejected": rejected,
        "pending": sum(1 for p in proposals if p.get("approval_status") == "PENDING"),
    }
