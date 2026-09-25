#!/usr/bin/env python3
"""
Adversarial Configuration Benchmark — docs/Suggestions.md §6, docs/action.md
Phase 4.

Same "no benchmark number is committed" discipline as
benchmarks/score_demo_results.py: every metric here is computed from real,
checkable output, not fabricated or asserted. Two tiers of metrics:

  1. Offline-computable (this script computes these directly, every run,
     no server needed): extraction accuracy and vendor-detection accuracy
     against the golden corpus (compare/), and whether each adversarial/
     fixture's *deterministic* cross-check output matches what its own
     .expected.json says was verified offline when the fixture was authored.

  2. Live-pipeline-only: parser disagreement against the real SLM, schema
     rejection rate, policy-result deviation, human-review rate, false
     acceptance rate, and the "Unsafe Action Escape Rate" all need a real
     Parsing (+ Ollama or mock) and Compliance (+ OPA) run per fixture.
     This script reports these as "unavailable" unless --live-results is
     given a directory of captured <fixture>.json audit-run responses
     (same shape benchmarks/score_demo_results.py already expects) — it
     never invents a number for a metric it can't actually check.

Usage:
    python benchmarks/adversarial/run_adversarial_benchmark.py
    python benchmarks/adversarial/run_adversarial_benchmark.py \
        --live-results benchmark-results --output benchmark-results/adversarial-metrics.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

BENCHMARK_DIR = Path(__file__).parent
REPO_ROOT = BENCHMARK_DIR.parents[1]
CORPUS_DIR = BENCHMARK_DIR / "corpus"
ADVERSARIAL_DIR = BENCHMARK_DIR / "adversarial"
DEMO_DIR = REPO_ROOT / "demo"

sys.path.insert(0, str(REPO_ROOT / "services" / "parsing"))
from app.deterministic_extractor import TextFSMExtractor  # noqa: E402
from app.vendor_detector import detect_vendor  # noqa: E402


def _flatten(data: dict, prefix: str = "") -> dict:
    flat = {}
    for key, value in data.items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            flat.update(_flatten(value, path))
        elif isinstance(value, list):
            flat[path] = json.dumps(
                sorted(json.dumps(item, sort_keys=True) for item in value)
            )
        else:
            flat[path] = value
    return flat


def score_corpus() -> dict:
    """Extraction accuracy + vendor-detection accuracy — fully offline,
    computed fresh every run against the same TextFSMExtractor Phase 1
    built and tested."""
    extractor = TextFSMExtractor()
    per_fixture = {}
    total_fields = correct_fields = 0
    vendor_correct = 0

    for golden_path in sorted(CORPUS_DIR.glob("*.expected.json")):
        fixture_name = golden_path.name.removesuffix(".expected.json")
        golden = json.loads(golden_path.read_text())
        config_text = (DEMO_DIR / fixture_name).read_text(encoding="utf-8")

        detected = detect_vendor(config_text)
        vendor_match = detected.vendor == golden["vendor"]
        vendor_correct += int(vendor_match)

        actual = extractor.extract(config_text, golden["vendor"])
        expected_flat = _flatten(golden["expected_baseline"])
        actual_flat = _flatten(actual)

        fields_total = len(expected_flat)
        fields_correct = sum(
            1 for path, value in expected_flat.items() if actual_flat.get(path) == value
        )
        total_fields += fields_total
        correct_fields += fields_correct

        per_fixture[fixture_name] = {
            "vendor_detected_correctly": vendor_match,
            "fields_expected": fields_total,
            "fields_correct": fields_correct,
            "field_accuracy": fields_correct / fields_total if fields_total else 1.0,
            "mismatched_fields": sorted(
                path for path, value in expected_flat.items() if actual_flat.get(path) != value
            ),
        }

    return {
        "fixture_count": len(per_fixture),
        "vendor_detection_accuracy": vendor_correct / len(per_fixture) if per_fixture else 1.0,
        "field_extraction_accuracy": correct_fields / total_fields if total_fields else 1.0,
        "fixtures": per_fixture,
    }


def score_adversarial_classes() -> dict:
    """Re-runs the deterministic extractor against each adversarial/
    fixture and checks it against the *offline-verifiable* claim in its own
    .expected.json (deterministic_extractor_actual_output*) — proves the
    fixture's documented behavior still holds, not a live-pipeline verdict."""
    extractor = TextFSMExtractor()
    results = {}

    for golden_path in sorted(ADVERSARIAL_DIR.glob("*.expected.json")):
        fixture_name = golden_path.name.removesuffix(".expected.json")
        golden = json.loads(golden_path.read_text())
        config_text = (ADVERSARIAL_DIR / fixture_name).read_text(encoding="utf-8")
        actual = extractor.extract(config_text, golden["vendor"])

        checks = {}
        for key, expected_value in golden.items():
            if not key.startswith("deterministic_extractor_actual_output"):
                continue
            # "deterministic_extractor_actual_output" (whole baseline) or
            # "deterministic_extractor_actual_output_telnet" (one section).
            suffix = key[len("deterministic_extractor_actual_output"):].lstrip("_")
            actual_value = actual.get(suffix) if suffix else actual
            checks[key] = {"expected": expected_value, "actual": actual_value, "match": actual_value == expected_value}

        results[fixture_name] = {
            "class": golden.get("class"),
            "expected_outcome": golden.get("expected_outcome"),
            "requires_live_pipeline_for_full_verdict": golden.get("requires_live_pipeline_for_full_verdict", False),
            "offline_checks": checks,
            "offline_checks_pass": all(c["match"] for c in checks.values()) if checks else None,
        }

    return results


EXPECTED_FINDINGS_PATH = DEMO_DIR / "expected-findings.json"

# docs/Suggestions.md §6's four test classes name what a correct live run
# must do with each; only these three actually require the pipeline to
# escalate rather than cleanly accept. "adversarial" is deliberately not
# scored against a required-escalation outcome the same way: its own
# .expected.json fixture (adversarial_disguised_telnet.cfg) says the
# correct behavior is to still surface the disguised finding through the
# normal compliance path, not necessarily reach human_review/BLOCK — so
# "did the finding survive the decoy" is checked directly against its
# `decisions`/`findings`, not folded into this escape check.
REQUIRED_ESCALATION_CLASSES = {"ambiguous", "malformed"}


def _policy_result_deviation(fixtures_checked: dict[str, dict]) -> dict | None:
    """docs/Suggestions.md §6's "policy-result deviation": compares the live
    run's OPA findings against demo/expected-findings.json's independently
    authored `must_include` list — the only ground truth this repo has for
    "what should Compliance conclude" (see benchmarks/README.md's own
    three-fixture caveat). Returns None, not a fabricated rate, when none of
    the checked fixtures have that ground truth."""
    if not EXPECTED_FINDINGS_PATH.exists():
        return None
    golden_findings = json.loads(EXPECTED_FINDINGS_PATH.read_text())["fixtures"]

    per_fixture = {}
    for fixture_name, golden in golden_findings.items():
        result = fixtures_checked.get(fixture_name)
        if result is None:
            continue
        actual_ids = {f.get("control_id") for f in result.get("findings", [])}
        missing = sorted(set(golden.get("must_include", [])) - actual_ids)
        unexpected = sorted(set(golden.get("must_exclude", [])) & actual_ids)
        per_fixture[fixture_name] = {
            "missing_required_findings": missing,
            "unexpected_findings": unexpected,
            "matched": not missing and not unexpected,
        }

    if not per_fixture:
        return None
    return {
        "fixtures_with_ground_truth": sorted(per_fixture),
        "deviation_rate": sum(1 for v in per_fixture.values() if not v["matched"]) / len(per_fixture),
        "fixtures": per_fixture,
    }


def _unsafe_action_escape_rate(fixtures_checked: dict[str, dict]) -> dict | None:
    """docs/Suggestions.md §6's "Unsafe Action Escape Rate": for a fixture
    whose own class requires escalation (human review or schema rejection —
    REQUIRED_ESCALATION_CLASSES), an "escape" is the live run instead
    reaching a clean, auto-approvable decision with nothing flagging it —
    the exact failure this metric exists to catch. A fixture the pipeline
    correctly escalated (human_review status, or every decision landing on
    BLOCK/DUAL_APPROVAL) is not an escape."""
    scored = {
        name: result for name, result in fixtures_checked.items()
        if result.get("class") in REQUIRED_ESCALATION_CLASSES
    }
    if not scored:
        return None

    escapes = {}
    for name, result in scored.items():
        escalated = result.get("status") == "human_review" or any(
            d["action"] in ("BLOCK", "DUAL_APPROVAL") for d in result.get("decisions", [])
        )
        escapes[name] = not escalated

    return {
        "fixtures_scored": sorted(scored),
        "escape_rate": sum(escapes.values()) / len(escapes),
        "escaped_fixtures": sorted(name for name, escaped in escapes.items() if escaped),
    }


def score_live_results(results_dir: Path) -> dict | None:
    """Metrics that need a real pipeline run — reads captured
    <fixture>.json audit-run responses the same way
    benchmarks/score_demo_results.py does. Returns None (not fabricated
    zeros) when results_dir wasn't given."""
    if results_dir is None:
        return None

    fixtures = list(CORPUS_DIR.glob("*.expected.json")) + list(ADVERSARIAL_DIR.glob("*.expected.json"))
    human_review = disagreements = checked = 0
    missing = []
    fixtures_checked: dict[str, dict] = {}
    for golden_path in fixtures:
        fixture_name = golden_path.name.removesuffix(".expected.json")
        result_path = results_dir / f"{fixture_name}.json"
        if not result_path.exists():
            missing.append(fixture_name)
            continue
        checked += 1
        result = json.loads(result_path.read_text())
        fixtures_checked[fixture_name] = result
        if result.get("status") == "human_review":
            human_review += 1
        agreement = result.get("parser_agreement")
        if agreement is not None and agreement < 1.0:
            disagreements += 1

    return {
        "fixtures_checked": checked,
        "fixtures_missing_captured_output": missing,
        "human_review_rate": human_review / checked if checked else None,
        "parser_disagreement_rate": disagreements / checked if checked else None,
        "policy_result_deviation": _policy_result_deviation(fixtures_checked),
        "unsafe_action_escape_rate": _unsafe_action_escape_rate(fixtures_checked),
        # False acceptance rate needs a ground-truth "should this have been
        # accepted at all" label per fixture, which this repo only has via
        # the same must_include list policy_result_deviation already reads —
        # a fixture with zero missing required findings and a SAFE/AUTO
        # decision is the "true accept" case that rate would need to
        # distinguish from a false one, and with only 3 ground-truth
        # fixtures there isn't a real negative-class example to score against.
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--live-results", type=Path, default=None,
        help="Directory of captured <fixture>.json audit-run responses from a real pipeline run",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    report = {
        "corpus": score_corpus(),
        "adversarial_classes": score_adversarial_classes(),
        "live_pipeline_metrics": score_live_results(args.live_results),
    }
    rendered = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered)
    print(rendered, end="")

    corpus_ok = report["corpus"]["field_extraction_accuracy"] == 1.0 and report["corpus"]["vendor_detection_accuracy"] == 1.0
    adversarial_ok = all(
        v["offline_checks_pass"] is not False for v in report["adversarial_classes"].values()
    )
    return 0 if corpus_ok and adversarial_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
