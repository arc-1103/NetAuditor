#!/usr/bin/env python3
"""Score live audit JSON against reviewed demo expectations.

No benchmark number is committed: metrics are computed only from captured
system output, preventing aspirational figures from being presented as facts.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("results", type=Path, help="Directory containing <fixture>.json audit responses")
    parser.add_argument("--expectations", type=Path, default=Path("demo/expected-findings.json"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    expected = json.loads(args.expectations.read_text())["fixtures"]
    tp = fp = fn = 0
    per_fixture = {}
    for fixture, rules in expected.items():
        path = args.results / f"{fixture}.json"
        result = json.loads(path.read_text())
        actual = {item["control_id"] for item in result.get("findings", [])}
        positives = set(rules.get("must_include", []))
        negatives = set(rules.get("must_exclude", []))
        fixture_tp = len(actual & positives)
        fixture_fn = len(positives - actual)
        fixture_fp = len(actual & negatives)
        tp += fixture_tp; fn += fixture_fn; fp += fixture_fp
        per_fixture[fixture] = {
            "expected_vendor": rules["vendor"],
            "detected_vendor": result.get("device", {}).get("detected_vendor"),
            "true_positives": fixture_tp,
            "false_negatives": fixture_fn,
            "false_positives": fixture_fp,
        }
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    report = {"sample_count": len(expected), "precision": precision, "recall": recall, "fixtures": per_fixture}
    rendered = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered)
    print(rendered, end="")
    return 0 if fp == 0 and fn == 0 and all(x["expected_vendor"] == x["detected_vendor"] for x in per_fixture.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
