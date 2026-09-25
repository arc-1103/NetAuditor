"""Unit tests for the two live-pipeline metrics run_adversarial_benchmark.py
computes from captured results — docs/action.md Phase 4's follow-up note."""

import importlib.util
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("run_adversarial_benchmark", Path(__file__).parent / "run_adversarial_benchmark.py")
mod = importlib.util.module_from_spec(spec)
sys.modules["run_adversarial_benchmark"] = mod
spec.loader.exec_module(mod)


def test_policy_result_deviation_flags_a_missing_required_finding():
    fixtures_checked = {
        "cisco_insecure.cfg": {"findings": [{"control_id": "CIS-NET-1.1.1"}]},  # missing several required ids
    }
    result = mod._policy_result_deviation(fixtures_checked)

    assert "cisco_insecure.cfg" in result["fixtures_with_ground_truth"]
    assert result["fixtures"]["cisco_insecure.cfg"]["matched"] is False
    assert "CIS-NET-1.1.2" in result["fixtures"]["cisco_insecure.cfg"]["missing_required_findings"]
    assert result["deviation_rate"] == 1.0


def test_policy_result_deviation_is_none_without_any_ground_truth_fixture():
    assert mod._policy_result_deviation({"cisco_weak_crypto.cfg": {"findings": []}}) is None


def test_policy_result_deviation_flags_an_unexpected_finding_on_a_must_exclude_fixture():
    fixtures_checked = {
        "cisco_hardened.cfg": {"findings": [{"control_id": "CIS-NET-1.1.2"}]},  # hardened config must NOT have this
    }
    result = mod._policy_result_deviation(fixtures_checked)

    assert result["fixtures"]["cisco_hardened.cfg"]["matched"] is False
    assert "CIS-NET-1.1.2" in result["fixtures"]["cisco_hardened.cfg"]["unexpected_findings"]


def test_unsafe_action_escape_rate_flags_an_ambiguous_fixture_that_cleanly_auto_approved():
    fixtures_checked = {
        "ambiguous_conflicting_vty_ranges.cfg": {
            "class": "ambiguous", "status": "submitted",
            "decisions": [{"control_id": "CIS-NET-1.1.2", "action": "SINGLE_APPROVAL"}],
        },
    }
    result = mod._unsafe_action_escape_rate(fixtures_checked)

    assert result["escape_rate"] == 1.0
    assert "ambiguous_conflicting_vty_ranges.cfg" in result["escaped_fixtures"]


def test_unsafe_action_escape_rate_is_not_an_escape_when_human_review_caught_it():
    fixtures_checked = {
        "malformed_truncated.cfg": {"class": "malformed", "status": "human_review", "decisions": []},
    }
    result = mod._unsafe_action_escape_rate(fixtures_checked)

    assert result["escape_rate"] == 0.0


def test_unsafe_action_escape_rate_is_not_an_escape_when_a_decision_blocked_it():
    fixtures_checked = {
        "ambiguous_conflicting_vty_ranges.cfg": {
            "class": "ambiguous", "status": "submitted",
            "decisions": [{"control_id": "CIS-NET-1.1.2", "action": "BLOCK"}],
        },
    }
    result = mod._unsafe_action_escape_rate(fixtures_checked)

    assert result["escape_rate"] == 0.0


def test_unsafe_action_escape_rate_is_none_for_fixtures_outside_the_required_classes():
    fixtures_checked = {
        "adversarial_disguised_telnet.cfg": {"class": "adversarial", "status": "submitted", "decisions": []},
    }
    assert mod._unsafe_action_escape_rate(fixtures_checked) is None
