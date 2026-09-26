"""Unit tests for app.decision — docs/Additional-Features.md §2's table."""

from app import decision


def test_auto_apply_at_high_confidence_zero_blast_radius_low_risk():
    result = decision.decide(parser_agreement=0.995, blast_radius=0, severity="LOW")
    assert result["action"] == "AUTO_APPLY"


def test_single_approval_at_high_confidence_small_blast_radius():
    result = decision.decide(parser_agreement=0.96, blast_radius=2, severity="MEDIUM")
    assert result["action"] == "SINGLE_APPROVAL"


def test_dual_approval_for_high_risk_reachability_change_even_at_high_confidence():
    """decision_table.yaml's dual-approval-high-risk-reachability-change:
    app/approval_matrix.py's docstring names this exact condition ("HIGH
    risk, reachability-changing -> 2-person rule") — high parser confidence
    must not downgrade it to a single approval."""
    result = decision.decide(parser_agreement=0.96, blast_radius=2, severity="HIGH")
    assert result["action"] == "DUAL_APPROVAL"
    assert result["rule_id"] == "dual-approval-high-risk-reachability-change"


def test_single_approval_for_high_risk_with_zero_blast_radius():
    """A single-device HIGH-risk change isn't "reachability-changing" in the
    sense the 2-person rule targets — only a nonzero blast radius escalates."""
    result = decision.decide(parser_agreement=0.96, blast_radius=0, severity="HIGH")
    assert result["action"] == "SINGLE_APPROVAL"


def test_auto_apply_does_not_fire_for_non_low_risk_even_at_full_confidence():
    result = decision.decide(parser_agreement=1.0, blast_radius=0, severity="CRITICAL")
    assert result["action"] != "AUTO_APPLY"


def test_dual_approval_in_the_90_to_95_percent_band():
    result = decision.decide(parser_agreement=0.92, blast_radius=0, severity="LOW")
    assert result["action"] == "DUAL_APPROVAL"


def test_block_below_90_percent_parser_agreement():
    result = decision.decide(parser_agreement=0.5, blast_radius=0, severity="LOW")
    assert result["action"] == "BLOCK"


def test_block_regardless_of_confidence_for_large_blast_radius():
    """docs/Additional-Features.md §2's last row: blocked regardless of
    confidence when the change reaches enough devices — no critical-service
    registry exists yet, so this is proxied by blast radius size (see
    decision_table.yaml's block-large-blast-radius rule)."""
    result = decision.decide(parser_agreement=1.0, blast_radius=5, severity="LOW")
    assert result["action"] == "BLOCK"
    assert result["rule_id"] == "block-large-blast-radius"


def test_missing_parser_agreement_is_treated_as_the_least_trustworthy_value():
    """A dry-run evaluation with no recorded parsing_confidence must not
    score more favorably than an actual low confidence would."""
    result = decision.decide(parser_agreement=None, blast_radius=0, severity="LOW")
    assert result["action"] == "BLOCK"


def test_every_decision_cites_the_ruleset_version():
    result = decision.decide(parser_agreement=0.5, blast_radius=0, severity="LOW")
    assert result["ruleset_version"] == "1.1.0"


def test_decision_echoes_risk_and_blast_radius_for_the_approval_matrix():
    """app/approval_matrix.py (docs/Additional-Features.md §7) must see the
    exact risk/blast-radius values that produced this action."""
    result = decision.decide(parser_agreement=0.5, blast_radius=3, severity="HIGH")
    assert result["risk"] == "HIGH"
    assert result["blast_radius_count"] == 3


def test_risk_for_severity_maps_critical_and_high_to_high_risk():
    assert decision.risk_for_severity("CRITICAL") == "HIGH"
    assert decision.risk_for_severity("HIGH") == "HIGH"
    assert decision.risk_for_severity("MEDIUM") == "MEDIUM"
    assert decision.risk_for_severity("LOW") == "LOW"


def test_risk_for_severity_defaults_unknown_to_high():
    assert decision.risk_for_severity("SOMETHING-NEW") == "HIGH"


def test_blast_radius_count_of_none_is_never_treated_as_zero():
    """A caller that forgets to pass blast_radius must not make a proposal
    look auto-apply-eligible."""
    assert decision.blast_radius_count(None) != 0
    result = decision.decide(
        parser_agreement=1.0, blast_radius=decision.blast_radius_count(None), severity="LOW"
    )
    assert result["action"] != "AUTO_APPLY"


def test_blast_radius_count_of_empty_list_is_zero():
    assert decision.blast_radius_count([]) == 0
