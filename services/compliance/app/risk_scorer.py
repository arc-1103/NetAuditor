"""
Risk Severity Scorer — blueprint §2.1, `System_Boundary(compliance)`.

Severity is decided in the Rego rule, not here, so the verdict stays
reproducible. This module only turns those severities into numbers the
dashboard and PDF report can rank and total.

Weights are a module constant rather than the YAML file the .env.example
originally pointed at: four integers that change roughly never don't earn a
config file, a parser, and a failure mode when it's missing.
"""

from collections import Counter

SEVERITY_WEIGHTS = {
    "CRITICAL": 40,
    "HIGH": 20,
    "MEDIUM": 10,
    "LOW": 5,
}

# A severity the Rego bundle emits that we don't know about must not score 0 —
# that would let a typo'd severity hide a real failure from the score.
UNKNOWN_SEVERITY_WEIGHT = SEVERITY_WEIGHTS["MEDIUM"]

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

# Every control the generic Level-1 bundle can fail
# (services/compliance/policies/generic/generic_level1.rego), mirrored here as
# plain data so a device's weighted compliance score has a real denominator —
# "how much of the framework did this device pass" — instead of the old
# undefined "100 - risk_score". A control absent from compliance_findings for
# an evaluated run is a pass by construction (see app/db.py's "a control that
# passed is simply absent"), so this catalog is what makes a pass countable
# at all: without it there is nothing to weight into a ratio's numerator.
#
# docs/Additional-Features.md §1 also names CIS Level 2 and STIG CAT I/II/III
# as weight tiers; this bundle only implements CIS Level 1, one severity per
# control, so every control here maps to its Rego severity via
# SEVERITY_WEIGHTS rather than a separate tier. Add a tier column the day a
# second framework/level bundle ships.
CONTROL_CATALOG = {
    "CIS-NET-1.1.1": "HIGH",
    "CIS-NET-1.1.2": "CRITICAL",
    "CIS-NET-1.1.3": "HIGH",
    "CIS-NET-1.2.1": "HIGH",
    "CIS-NET-1.2.2": "CRITICAL",
    "CIS-NET-1.3.1": "CRITICAL",
    "CIS-NET-1.4.1": "MEDIUM",
    "CIS-NET-1.5.1": "HIGH",
    "CIS-NET-1.6.1": "LOW",
    "CIS-NET-1.7.1": "MEDIUM",
    "CIS-NET-1.8.1": "MEDIUM",
}
CONTROL_WEIGHTS = {cid: SEVERITY_WEIGHTS[sev] for cid, sev in CONTROL_CATALOG.items()}

# Titles as written in generic_level1.rego — only failing controls carry a
# title in the database, so a PASS row needs its own copy. Keep in sync with
# the Rego file (and with services/reporting/app/scoring.py).
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


def score_finding(finding: dict) -> int:
    """Weight for one finding, by its severity."""
    severity = str(finding.get("severity", "")).upper()
    return SEVERITY_WEIGHTS.get(severity, UNKNOWN_SEVERITY_WEIGHT)


def score_findings(findings: list[dict]) -> list[dict]:
    """Return copies of `findings` with `risk_score` filled in."""
    return [{**f, "risk_score": score_finding(f)} for f in findings]


def compliance_score(findings: list[dict]) -> int:
    """docs/Additional-Features.md §1:

        Σ(control_weight × control_pass) / Σ(control_weight)

    over every control in CONTROL_CATALOG, `control_pass` = 0 for a control
    with a finding here, 1 otherwise. A finding for a control_id outside the
    catalog (an unrecognized/typo'd id) still has to count against the
    device — it's added to the universe at its own severity weight rather
    than silently ignored, the same fail-safe reasoning as
    UNKNOWN_SEVERITY_WEIGHT above.
    """
    failed = {f["control_id"]: score_finding(f) for f in findings if f.get("control_id")}
    universe = dict(CONTROL_WEIGHTS)
    for control_id, weight in failed.items():
        universe.setdefault(control_id, weight)
    total_weight = sum(universe.values())
    if total_weight == 0:
        return 100
    passed_weight = sum(weight for control_id, weight in universe.items() if control_id not in failed)
    return round((passed_weight / total_weight) * 100)


def summarize(findings: list[dict]) -> dict:
    """Roll scored findings up into the per-run summary the dashboard shows."""
    counts = Counter(str(f.get("severity", "")).upper() for f in findings)
    risk_score = sum(f.get("risk_score", score_finding(f)) for f in findings)

    failed_ids = {f.get("control_id") for f in findings if f.get("control_id")}
    evaluated = len(CONTROL_CATALOG | {cid: None for cid in failed_ids})
    failed = len(failed_ids)
    passed = max(0, evaluated - failed)
    return {
        "total_findings": len(findings),
        "by_severity": {level: counts.get(level, 0) for level in SEVERITY_ORDER},
        "risk_score": risk_score,
        "compliance_score": compliance_score(findings),
        "controls_evaluated": evaluated,
        "controls_failed": failed,
        "controls_passed": passed,
        "control_pass_rate": round((passed / evaluated) * 100) if evaluated else 0,
    }


def fleet_score(findings_by_run: dict[str, list[dict]]) -> dict:
    """Fleet-wide rollup — docs/Additional-Features.md §1: "not an average of
    device percentages, a device with 40 controls should count more than one
    with 4". So this sums weight across every run's control universe rather
    than averaging each run's own compliance_score.
    """
    total_weight = 0
    total_passed_weight = 0
    for findings in findings_by_run.values():
        failed = {f["control_id"]: score_finding(f) for f in findings if f.get("control_id")}
        universe = dict(CONTROL_WEIGHTS)
        for control_id, weight in failed.items():
            universe.setdefault(control_id, weight)
        total_weight += sum(universe.values())
        total_passed_weight += sum(w for cid, w in universe.items() if cid not in failed)
    return {
        "devices_scored": len(findings_by_run),
        "fleet_score": round((total_passed_weight / total_weight) * 100) if total_weight else 100,
    }
