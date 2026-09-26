"""Unit tests for the offline-computable parts of run_crag_eval.py — the
live-OPA parts (evidence_linking_live, verdict_reproducibility) need a real
OPA server and are exercised by running the script itself, not here."""

import importlib.util
import sys
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("run_crag_eval", Path(__file__).parent / "run_crag_eval.py")
mod = importlib.util.module_from_spec(spec)
sys.modules["run_crag_eval"] = mod
spec.loader.exec_module(mod)


def test_corpus_benchmark_covers_every_vendor_dialect():
    result = mod.corpus_benchmark()

    assert set(result["vendors"]) == set(mod.VENDOR_DIALECTS)
    for vendor, bucket in result["vendors"].items():
        assert bucket["dialect"] == mod.VENDOR_DIALECTS[vendor]
        assert bucket["fixture_count"] > 0
        assert 0.0 <= bucket["field_extraction_accuracy"] <= 1.0
        assert bucket["avg_latency_ms"] >= 0.0


def test_corpus_benchmark_is_perfect_on_the_golden_corpus():
    """Every corpus/*.expected.json is a label for the deterministic
    extractor's own output on that fixture — a mismatch here means either
    the extractor regressed or a golden file was hand-edited incorrectly."""
    result = mod.corpus_benchmark()

    for vendor, bucket in result["vendors"].items():
        assert bucket["field_extraction_accuracy"] == 1.0, f"{vendor}: {bucket['fixtures']}"


def test_evidence_coverage_has_no_uncovered_control_ids():
    result = mod.evidence_coverage()

    assert result["uncovered_control_ids"] == []
    assert result["coverage"] == 1.0
    assert len(result["control_ids"]) >= 11  # generic_level1.rego's 11-control illustrative subset


@pytest.mark.asyncio
async def test_remediation_safety_perfect_tp_and_zero_fp_on_curated_cases():
    result = await mod.remediation_safety()

    assert result["true_positive_rate"] == 1.0
    assert result["false_positive_rate"] == 0.0
    for case in result["cases"]:
        assert case["correct"], case


def test_remediation_safety_fixture_has_both_classes_represented():
    cases = __import__("json").loads(mod.REMEDIATION_FIXTURES.read_text())["cases"]

    assert any(c["expect_flagged"] for c in cases)
    assert any(not c["expect_flagged"] for c in cases)
