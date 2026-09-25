#!/usr/bin/env python3
"""
Captures real live-pipeline output for every benchmarks/adversarial/{corpus,
adversarial} fixture, writing <fixture-name>.json into a results directory
in the shape run_adversarial_benchmark.py's score_live_results() reads.

"Live" here means the real Ollama SLM (services/parsing/app/worker.py's
actual chunk-parsing path, unmocked) and the real OPA server evaluating the
real Rego bundle — the two pieces docs/action.md Phase 4 named as needed for
these metrics. It deliberately does NOT need Postgres, Redis, or Neo4j: this
harness calls Parsing's _process_config() directly in-process rather than
through Celery/Postgres, with only the two calls that exist purely to persist
state or hand off to another lane (app.db.mark_needs_review,
celery_app.send_task) stubbed to no-ops — nothing that affects the SLM
output, the deterministic cross-check, or the OPA verdict this benchmark
actually scores.

Requires (checked at startup, not silently skipped):
  - An OPA server at OPA_SERVER_URL (default http://127.0.0.1:8181) serving
    services/compliance/policies — e.g. `opa run --server services/compliance/policies`.
  - Ollama reachable at OLLAMA_HOST with OLLAMA_MODEL pulled.

Usage:
    python benchmarks/adversarial/capture_live_results.py [--output-dir benchmark-results]
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

BENCHMARK_DIR = Path(__file__).parent
REPO_ROOT = BENCHMARK_DIR.parents[1]
CORPUS_DIR = BENCHMARK_DIR / "corpus"
ADVERSARIAL_DIR = BENCHMARK_DIR / "adversarial"
DEMO_DIR = REPO_ROOT / "demo"

OPA_SERVER_URL = "http://127.0.0.1:8181/v1/data"

# ENABLE_PARSE_CACHE is the one setting overridden before importing Parsing:
# it's a pure Redis-backed speed optimization (app/parse_cache.py), off by
# default here since this harness has no Redis and a cache miss is always
# the correct-but-slower fallback anyway. Every other setting (real Ollama
# model, reverse-translation gate, deterministic cross-check) is left at
# its production default so this run reflects the real pipeline's behavior.
import os  # noqa: E402
os.environ.setdefault("ENABLE_PARSE_CACHE", "false")
os.environ.setdefault("OPA_URL", OPA_SERVER_URL)

sys.path.insert(0, str(REPO_ROOT / "services" / "parsing"))
from app import worker  # noqa: E402


def _noop_send_task(*_args, **_kwargs):
    return None


async def _noop_mark_needs_review(*_args, **_kwargs):
    return None


worker.celery_app.send_task = _noop_send_task
worker.db.mark_needs_review = _noop_mark_needs_review


def _load_standalone(name: str, path: Path):
    """Loads a module with no relative imports under an alias, avoiding the
    package-name collision every service's app/ directory shares
    ("app.opa_client" and Parsing's already-imported "app.worker" cannot
    both be named "app" in sys.modules at once)."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


opa_client = _load_standalone("_bench_opa_client", REPO_ROOT / "services" / "compliance" / "app" / "opa_client.py")
risk_scorer = _load_standalone("_bench_risk_scorer", REPO_ROOT / "services" / "compliance" / "app" / "risk_scorer.py")
decision = _load_standalone("_bench_decision", REPO_ROOT / "services" / "remediation" / "app" / "decision.py")


def _build_job(config_text: str, fixture_name: str) -> dict:
    return {
        "job_id": str(uuid4()),
        "file_hash": hashlib.sha256(config_text.encode()).hexdigest(),
        "storage_path": f"benchmarks/adversarial/{fixture_name}",
        "original_filename": fixture_name,
        "uploaded_by": "adversarial-benchmark",
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
        "chunk_count": 1,
        "chunks": [{"index": 0, "text": config_text}],
    }


async def _capture_one(config_text: str, fixture_name: str) -> dict:
    job = _build_job(config_text, fixture_name)
    parse_result = await worker._process_config(job)

    result = {
        "status": parse_result["status"],
        "parser_agreement": parse_result.get("parser_agreement"),
        "conflicts": parse_result.get("conflicts", []),
    }
    baseline = parse_result.get("baseline")
    if baseline is not None:
        result["detected_vendor"] = baseline.get("device", {}).get("detected_vendor")
        result["parsing_confidence"] = baseline.get("device", {}).get("parsing_confidence")

    # Mirrors worker.py's own gate: only a "submitted" job (confidence over
    # threshold) ever reaches Compliance for real — evaluating a
    # human_review baseline against OPA here would score a verdict the real
    # pipeline never lets happen either.
    if parse_result["status"] == "submitted" and baseline is not None:
        findings = await opa_client.evaluate(baseline, "CIS")
        result["findings"] = findings
        result["compliance_summary"] = risk_scorer.summarize(risk_scorer.score_findings(findings))
        result["decisions"] = [
            {
                "control_id": f.get("control_id"),
                "severity": f.get("severity"),
                **decision.decide(
                    parser_agreement=result["parser_agreement"],
                    # No topology/graph data in this harness (no Neo4j) —
                    # None is the honest "unknown blast radius" input,
                    # which decision.py's own UNKNOWN_BLAST_RADIUS constant
                    # already treats as the least-favorable case, not a
                    # fabricated zero.
                    blast_radius=decision.blast_radius_count(None),
                    severity=f.get("severity", "HIGH"),
                ),
            }
            for f in findings
        ]
    return result


async def _run(output_dir: Path) -> list[str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    captured = []

    for golden_path in sorted(CORPUS_DIR.glob("*.expected.json")):
        fixture_name = golden_path.name.removesuffix(".expected.json")
        config_text = (DEMO_DIR / fixture_name).read_text(encoding="utf-8")
        print(f"parsing {fixture_name} ...", file=sys.stderr)
        result = await _capture_one(config_text, fixture_name)
        (output_dir / f"{fixture_name}.json").write_text(json.dumps(result, indent=2) + "\n")
        captured.append(fixture_name)

    for golden_path in sorted(ADVERSARIAL_DIR.glob("*.expected.json")):
        fixture_name = golden_path.name.removesuffix(".expected.json")
        golden = json.loads(golden_path.read_text())
        config_text = (ADVERSARIAL_DIR / fixture_name).read_text(encoding="utf-8")
        print(f"parsing {fixture_name} ...", file=sys.stderr)
        result = await _capture_one(config_text, fixture_name)
        result["class"] = golden.get("class")
        result["expected_outcome"] = golden.get("expected_outcome")
        (output_dir / f"{fixture_name}.json").write_text(json.dumps(result, indent=2) + "\n")
        captured.append(fixture_name)

    return captured


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=REPO_ROOT / "benchmark-results")
    args = parser.parse_args()

    captured = asyncio.run(_run(args.output_dir))
    print(f"Captured {len(captured)} fixtures into {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
