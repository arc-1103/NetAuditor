"""Unit tests for app.trust — docs/Suggestions.md item 7, docs/action.md Phase 3."""

from app.trust import build_trust_view


def test_empty_deterministic_baseline_produces_no_fields():
    """An unsupported vendor (deterministic_baseline={}) must return an
    empty comparison, not a false wall of disagreements."""
    view = build_trust_view({"ssh": {"version": "2"}}, {}, None)

    assert view["fields"] == []
    assert view["fields_compared"] == 0
    assert view["parser_agreement"] is None


def test_matching_scalar_field_is_reported_as_agreement():
    view = build_trust_view(
        {"ssh": {"version": "2"}}, {"ssh": {"version": "2"}}, 1.0,
    )

    assert view["fields"] == [{
        "field": "ssh.version", "slm_value": "2", "deterministic_value": "2",
        "agree": True, "source": "agreement",
    }]


def test_disagreeing_scalar_field_is_reported():
    view = build_trust_view(
        {"telnet": {"enabled": "DISABLED"}}, {"telnet": {"enabled": "ENABLED"}}, 0.0,
    )

    assert view["fields"][0]["agree"] is False
    assert view["fields"][0]["source"] == "disagreement"
    assert view["fields"][0]["slm_value"] == "DISABLED"
    assert view["fields"][0]["deterministic_value"] == "ENABLED"


def test_slm_field_the_deterministic_side_never_touched_is_not_reported():
    view = build_trust_view(
        {"ssh": {"version": "2"}, "aaa": {"authorization_enabled": True}}, {"ssh": {"version": "2"}}, 1.0,
    )

    fields = [f["field"] for f in view["fields"]]
    assert fields == ["ssh.version"]


def test_slm_missing_a_field_the_deterministic_side_found_is_a_disagreement():
    view = build_trust_view({}, {"banners": {"login_banner_present": True}}, 0.0)

    assert view["fields"][0]["slm_value"] is None
    assert view["fields"][0]["deterministic_value"] is True
    assert view["fields"][0]["agree"] is False


def test_list_fields_compare_order_independently():
    """Two IKE policy lists with the same content in a different order (and
    different dict key order) must agree — the diff isn't a literal
    equality check, see app.trust._values_agree."""
    slm = {"crypto": {"ike_policies": [
        {"policy_id": 10, "encryption": "AES256"},
        {"policy_id": 20, "encryption": "DES"},
    ]}}
    deterministic = {"crypto": {"ike_policies": [
        {"encryption": "DES", "policy_id": 20},
        {"encryption": "AES256", "policy_id": 10},
    ]}}

    view = build_trust_view(slm, deterministic, 1.0)

    assert view["fields"][0]["agree"] is True


def test_list_fields_with_different_content_disagree():
    slm = {"crypto": {"ike_policies": [{"policy_id": 10, "encryption": "AES256"}]}}
    deterministic = {"crypto": {"ike_policies": [{"policy_id": 10, "encryption": "3DES"}]}}

    view = build_trust_view(slm, deterministic, 0.0)

    assert view["fields"][0]["agree"] is False


def test_none_baselines_do_not_raise():
    view = build_trust_view(None, None, None)

    assert view == {"parser_agreement": None, "fields_compared": 0, "fields": []}
