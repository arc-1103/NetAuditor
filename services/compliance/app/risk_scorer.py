"""
Risk Severity Scorer — blueprint §2.1, `System_Boundary(compliance)`.

Severity is decided in the Rego rule, not here, so the verdict stays
reproducible. This module only turns those severities into numbers the
dashboard and PDF report can rank and total.

Weights are a module constant rather than the YAML file the .env.example
originally pointed at: four integers that change roughly never don't earn a
config file, a parser, and a failure mode when it's missing.
"""

import os
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
CONTROLS_EVALUATED = int(os.getenv("CONTROLS_EVALUATED", "11"))


def score_finding(finding: dict) -> int:
    """Weight for one finding, by its severity."""
    severity = str(finding.get("severity", "")).upper()
    return SEVERITY_WEIGHTS.get(severity, UNKNOWN_SEVERITY_WEIGHT)


def score_findings(findings: list[dict]) -> list[dict]:
    """Return copies of `findings` with `risk_score` filled in."""
    return [{**f, "risk_score": score_finding(f)} for f in findings]


def summarize(findings: list[dict]) -> dict:
    """Roll scored findings up into the per-run summary the dashboard shows.

    `compliance_score` is 100 minus the accumulated risk, floored at 0 — a
    device with eight criticals is not "minus 220% compliant", it's 0.
    """
    counts = Counter(str(f.get("severity", "")).upper() for f in findings)
    risk_score = sum(f.get("risk_score", score_finding(f)) for f in findings)

    failed = len({f.get("control_id") for f in findings if f.get("control_id")})
    evaluated = max(CONTROLS_EVALUATED, failed)
    passed = max(0, evaluated - failed)
    return {
        "total_findings": len(findings),
        "by_severity": {level: counts.get(level, 0) for level in SEVERITY_ORDER},
        "risk_score": risk_score,
        "compliance_score": max(0, 100 - risk_score),
        "controls_evaluated": evaluated,
        "controls_failed": failed,
        "controls_passed": passed,
        "control_pass_rate": round((passed / evaluated) * 100) if evaluated else 0,
    }
