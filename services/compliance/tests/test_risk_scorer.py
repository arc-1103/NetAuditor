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


def test_summarize_of_clean_device_is_fully_compliant():
    summary = risk_scorer.summarize([])

    assert summary["total_findings"] == 0
    assert summary["risk_score"] == 0
    assert summary["compliance_score"] == 100
    assert summary["controls_evaluated"] == len(risk_scorer.CONTROL_CATALOG)
    assert summary["controls_passed"] == len(risk_scorer.CONTROL_CATALOG)


def test_summarize_scores_findings_that_were_not_pre_scored():
    summary = risk_scorer.summarize([_finding("HIGH")])

    assert summary["risk_score"] == 20


def test_compliance_score_is_weighted_pass_rate_over_the_catalog():
    """docs/Additional-Features.md §1's formula: fail one CRITICAL (weight 40)
    control out of the catalog's total weight — score is the remaining
    weight's share, not 100 minus an arbitrary point deduction."""
    findings = risk_scorer.score_findings([_finding("CRITICAL", "CIS-NET-1.1.2")])
    total_weight = sum(risk_scorer.CONTROL_WEIGHTS.values())

    summary = risk_scorer.summarize(findings)

    expected = round((total_weight - 40) / total_weight * 100)
    assert summary["compliance_score"] == expected
    assert summary["controls_failed"] == 1
    assert summary["controls_evaluated"] == len(risk_scorer.CONTROL_CATALOG)


def test_compliance_score_is_zero_when_every_catalog_control_fails():
    findings = risk_scorer.score_findings([
        _finding(risk_scorer.CONTROL_CATALOG[cid], cid) for cid in risk_scorer.CONTROL_CATALOG
    ])

    assert risk_scorer.summarize(findings)["compliance_score"] == 0


def test_compliance_score_counts_an_unrecognized_control_id_against_the_device():
    """A finding for a control_id outside the catalog must still lower the
    score — it can't be silently excluded just because it's unrecognized."""
    findings = risk_scorer.score_findings([_finding("CRITICAL", "SOME-UNKNOWN-CONTROL")])

    summary = risk_scorer.summarize(findings)

    assert summary["compliance_score"] < 100
    assert summary["controls_evaluated"] == len(risk_scorer.CONTROL_CATALOG) + 1


def test_fleet_score_weights_by_control_count_not_by_averaging_percentages():
    """A device that fails one of its 11 controls should count more than an
    equally-review device that fails one of only 2 — fleet_score sums raw
    weight across devices rather than averaging each device's own percentage."""
    big_device = risk_scorer.score_findings([_finding("LOW", "CIS-NET-1.6.1")])  # 1 of 11 controls
    small_device = risk_scorer.score_findings([_finding("CRITICAL", "ONLY-CONTROL")])  # 1 of 1 control

    result = risk_scorer.fleet_score({"run-a": big_device, "run-b": small_device})

    naive_average = round((risk_scorer.summarize(big_device)["compliance_score"]
                            + risk_scorer.summarize(small_device)["compliance_score"]) / 2)
    assert result["devices_scored"] == 2
    assert result["fleet_score"] != naive_average
