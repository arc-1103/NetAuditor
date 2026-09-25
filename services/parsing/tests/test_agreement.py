"""Unit tests for app.agreement — docs/action.md Phase 2."""

from app.agreement import compute_agreement


def test_no_comparison_when_deterministic_extractor_abstains_entirely():
    """Unsupported vendor / nothing extracted — agreement is None, not 0.0.
    "No comparison possible" and "everything disagreed" must stay distinct
    facts."""
    result = compute_agreement({"telnet": {"enabled": "ENABLED"}}, {})

    assert result.agreement is None
    assert result.compared_fields == 0
    assert result.disagreements == []


def test_full_agreement_on_matching_fields():
    slm = {"telnet": {"enabled": "ENABLED"}, "ssh": {"version": "2"}}
    deterministic = {"telnet": {"enabled": "ENABLED"}, "ssh": {"version": "2"}}

    result = compute_agreement(slm, deterministic)

    assert result.agreement == 1.0
    assert result.compared_fields == 2
    assert result.agreed_fields == 2
    assert result.disagreements == []


def test_partial_disagreement_is_scored_and_named():
    slm = {"telnet": {"enabled": "DISABLED"}, "ssh": {"version": "2"}}
    deterministic = {"telnet": {"enabled": "ENABLED"}, "ssh": {"version": "2"}}

    result = compute_agreement(slm, deterministic)

    assert result.compared_fields == 2
    assert result.agreed_fields == 1
    assert result.agreement == 0.5
    assert result.disagreements == ["deterministic:telnet.enabled"]


def test_total_disagreement_scores_zero_not_none():
    slm = {"telnet": {"enabled": "DISABLED"}}
    deterministic = {"telnet": {"enabled": "ENABLED"}}

    result = compute_agreement(slm, deterministic)

    assert result.agreement == 0.0


def test_slm_fields_the_deterministic_extractor_never_touched_are_ignored():
    """The SLM extracts far more than the deterministic parser's scoped
    fields (docs/action.md) — those extra SLM fields must never lower the
    score just because the deterministic side has nothing to say about them."""
    slm = {"telnet": {"enabled": "ENABLED"}, "aaa": {"authorization_enabled": True}}
    deterministic = {"telnet": {"enabled": "ENABLED"}}

    result = compute_agreement(slm, deterministic)

    assert result.agreement == 1.0
    assert result.compared_fields == 1


def test_as_dict_round_trips_every_field():
    result = compute_agreement({"telnet": {"enabled": "ENABLED"}}, {"telnet": {"enabled": "ENABLED"}})

    assert result.as_dict() == {
        "agreement": 1.0, "compared_fields": 1, "agreed_fields": 1, "disagreements": [],
    }
