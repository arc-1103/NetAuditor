"""
Compliance scoring — docs/Additional-Features.md §1.

Split out of app/pdf_service.py so anything that only needs the scoring
formula (app/executive_report.py) doesn't transitively import WeasyPrint,
which pdf_service.py needs for actual PDF rendering and which isn't always
installable (native libgobject dependency — see pdf_service.py's own
history).

Kept identical to services/compliance/app/risk_scorer.py's CONTROL_CATALOG —
this service has no shared package to import it from (each service owns its
own summary logic), so this is the same duplication that already existed
for SEVERITY_WEIGHTS. A control added to
services/compliance/policies/generic/generic_level1.rego must be added here
too or this service's compliance_score will drift from the dashboard's.
"""

from collections import Counter

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
SEVERITY_WEIGHTS = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 5}
UNKNOWN_SEVERITY_WEIGHT = SEVERITY_WEIGHTS["MEDIUM"]
CONTROL_CATALOG = {
    "CIS-NET-1.1.1": "HIGH", "CIS-NET-1.1.2": "CRITICAL", "CIS-NET-1.1.3": "HIGH",
    "CIS-NET-1.2.1": "HIGH", "CIS-NET-1.2.2": "CRITICAL", "CIS-NET-1.3.1": "CRITICAL",
    "CIS-NET-1.4.1": "MEDIUM", "CIS-NET-1.5.1": "HIGH", "CIS-NET-1.6.1": "LOW",
    "CIS-NET-1.7.1": "MEDIUM", "CIS-NET-1.8.1": "MEDIUM",
}
CONTROL_WEIGHTS = {cid: SEVERITY_WEIGHTS[sev] for cid, sev in CONTROL_CATALOG.items()}


def weight(finding: dict) -> int:
    return SEVERITY_WEIGHTS.get(str(finding.get("severity", "")).upper(), UNKNOWN_SEVERITY_WEIGHT)


def summarize(findings: list[dict]) -> dict:
    """docs/Additional-Features.md §1's weighted formula — see
    services/compliance/app/risk_scorer.compliance_score for the full
    rationale."""
    counts = Counter(str(f.get("severity", "")).upper() for f in findings)
    risk = sum(int(f.get("risk_score", 0)) for f in findings)

    failed = {f["control_id"]: weight(f) for f in findings if f.get("control_id")}
    universe = dict(CONTROL_WEIGHTS)
    for control_id, control_weight in failed.items():
        universe.setdefault(control_id, control_weight)
    total_weight = sum(universe.values())
    passed_weight = sum(w for cid, w in universe.items() if cid not in failed)
    compliance_score = round((passed_weight / total_weight) * 100) if total_weight else 100

    evaluated = len(universe)
    controls_failed = len(failed)
    passed = max(0, evaluated - controls_failed)
    return {
        "total_findings": len(findings),
        "by_severity": {level: counts[level] for level in SEVERITY_ORDER},
        "risk_score": risk,
        "compliance_score": compliance_score,
        "controls_evaluated": evaluated,
        "controls_failed": controls_failed,
        "controls_passed": passed,
        "control_pass_rate": round((passed / evaluated) * 100) if evaluated else 0,
    }


def fleet_score(findings_by_run: dict[str, list[dict]]) -> dict:
    """docs/Additional-Features.md §1: "not an average of device
    percentages, a device with 40 controls should count more than one with
    4" — sums weight across every run's control universe rather than
    averaging each run's own compliance_score."""
    total_weight = 0
    total_passed_weight = 0
    for findings in findings_by_run.values():
        failed = {f["control_id"]: weight(f) for f in findings if f.get("control_id")}
        universe = dict(CONTROL_WEIGHTS)
        for control_id, control_weight in failed.items():
            universe.setdefault(control_id, control_weight)
        total_weight += sum(universe.values())
        total_passed_weight += sum(w for cid, w in universe.items() if cid not in failed)
    return {
        "devices_scored": len(findings_by_run),
        "fleet_score": round((total_passed_weight / total_weight) * 100) if total_weight else 100,
    }


# Titles as written in generic_level1.rego — only failing controls carry a
# title in the database, so a PASS row needs its own copy. Keep in sync with
# the Rego file (and with services/compliance/app/risk_scorer.py, which this duplicates).
CONTROL_TITLES = {
    "CIS-NET-1.1.1": "Ensure SSH version 2 is configured where SSH is in use",
    "CIS-NET-1.1.2": "Ensure Telnet is not used for administrative access",
    "CIS-NET-1.1.3": "Ensure SSH management access is restricted by an ACL",
    "CIS-NET-1.2.1": "Ensure SNMP is not using version 1 or 2c",
    "CIS-NET-1.2.2": "Ensure default SNMP community strings are not used",
    "CIS-NET-1.3.1": "Ensure IKE/IPsec Phase 1 proposals do not use DES or 3DES encryption",
    "CIS-NET-1.4.1": "Ensure NTP authentication is enabled where NTP is in use",
    "CIS-NET-1.5.1": "Ensure stored passwords/secrets are not left unencrypted",
    "CIS-NET-1.6.1": "Ensure a legal login banner is configured",
    "CIS-NET-1.7.1": "Ensure unencrypted HTTP administrative access is disabled",
    "CIS-NET-1.8.1": "Ensure logging is sent to a remote syslog host",
}


def control_results(findings: list[dict]) -> list[dict]:
    """Explicit PASS/FAIL per control, worst severity first: every catalog
    control plus any failing control outside it."""
    failed = {f["control_id"]: f for f in findings if f.get("control_id")}
    rows = []
    for control_id in {**CONTROL_CATALOG, **{cid: None for cid in failed}}:
        finding = failed.get(control_id)
        severity = str(finding["severity"]).upper() if finding else CONTROL_CATALOG.get(control_id, "MEDIUM")
        rows.append({
            "control_id": control_id,
            "title": (finding or {}).get("title") or CONTROL_TITLES.get(control_id, control_id),
            "result": ("WAIVED" if finding.get("waiver") else "FAIL") if finding else "PASS",
            "severity": severity,
            **({"waiver": finding["waiver"]} if finding and finding.get("waiver") else {}),
        })
    order = {level: i for i, level in enumerate(SEVERITY_ORDER)}
    rank = {"FAIL": 0, "WAIVED": 1, "PASS": 2}
    return sorted(rows, key=lambda r: (rank[r["result"]], order.get(r["severity"], 9), r["control_id"]))
