"""Unit tests for app.risk_scorer."""

from app import risk_scorer


def _finding(severity, control_id="CIS-IOS-1.1.1"):
    return {"control_id": control_id, "severity": severity}


def test_score_finding_uses_severity_weight():
    assert risk_scorer.score_finding(_finding("CRITICAL")) == 40
    assert risk_scorer.score_finding(_finding("LOW")) == 5


def test_score_finding_is_case_insensitive():
    assert risk_scorer.score_finding(_finding("critical")) == 40


def test_unknown_severity_does_not_score_zero():
    """A typo'd severity in a .rego file must not silently hide a failure."""
    assert risk_scorer.score_finding(_finding("SEVERE")) > 0
    assert risk_scorer.score_finding({}) > 0


def test_score_findings_adds_risk_score_without_mutating_input():
    findings = [_finding("HIGH")]

    scored = risk_scorer.score_findings(findings)

    assert scored[0]["risk_score"] == 20
    assert "risk_score" not in findings[0]


def test_summarize_counts_by_severity():
    findings = risk_scorer.score_findings([
        _finding("CRITICAL", "a"),
        _finding("CRITICAL", "b"),
        _finding("MEDIUM", "c"),
    ])

    summary = risk_scorer.summarize(findings)

    assert summary["total_findings"] == 3
    assert summary["by_severity"] == {"CRITICAL": 2, "HIGH": 0, "MEDIUM": 1, "LOW": 0}
    assert summary["risk_score"] == 90
    assert summary["compliance_score"] == 10


def test_summarize_of_clean_device_is_fully_compliant():
    summary = risk_scorer.summarize([])

    assert summary["total_findings"] == 0
    assert summary["risk_score"] == 0
    assert summary["compliance_score"] == 100


def test_compliance_score_floors_at_zero():
    """Eight criticals is 320 risk — the device is 0% compliant, not -220%."""
    findings = risk_scorer.score_findings([_finding("CRITICAL", str(i)) for i in range(8)])

    assert risk_scorer.summarize(findings)["compliance_score"] == 0


def test_summarize_scores_findings_that_were_not_pre_scored():
    summary = risk_scorer.summarize([_finding("HIGH")])

    assert summary["risk_score"] == 20
