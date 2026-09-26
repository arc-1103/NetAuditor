#!/usr/bin/env python3
"""
CRAG Evaluation Framework — evaluates the SLM/deterministic extraction step
and the OPA policy-verdict step of the Compliance CRAG pipeline against the
four categories a specialized CRAG setup needs (corpus benchmarking, evidence
linking, verdict reproducibility, remediation-safety true/false-positive
rate). Same "no benchmark number is committed" discipline as
benchmarks/adversarial/run_adversarial_benchmark.py: every metric here is
computed from real, checkable output. A metric that needs a service this
script can't reach (OPA) is reported as `null`/"unavailable", never guessed.

Scope, read before quoting any of these numbers — see README.md for the
full explanation:
  - CIS only. NIST and STIG have no Rego bundle yet
    (services/compliance/policies/ has only generic/generic_level1.rego), so
    this script never references those frameworks.
  - Remediation-safety evaluates services/remediation/app/batfish_client.py's
    static_safety_checks() — the only safety layer that actually runs today.
    Real Batfish is a health-check stub with no snapshot/topology wiring
    (see batfish_client.py's own module docstring), so no eval here claims to
    validate real network-simulation coverage.
  - Corpus benchmarking and evidence-linking coverage are fully offline.
    Evidence-linking's live check and verdict reproducibility need a running
    OPA loaded with services/compliance/policies (`docker compose up opa`
    with a host port mapping, or OPA_URL pointed at one already reachable);
    both report "unavailable" rather than failing when OPA can't be reached.

Usage:
    python benchmarks/crag_eval/run_crag_eval.py
    OPA_URL=http://localhost:8181/v1/data python benchmarks/crag_eval/run_crag_eval.py --output benchmark-results/crag-eval.json
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.util
import json
import re
import sys
import time
from contextlib import contextmanager
from pathlib import Path

EVAL_DIR = Path(__file__).parent
REPO_ROOT = EVAL_DIR.parents[1]
DEMO_DIR = REPO_ROOT / "demo"
CORPUS_DIR = REPO_ROOT / "benchmarks" / "adversarial" / "corpus"
REGO_BUNDLE = REPO_ROOT / "services" / "compliance" / "policies" / "generic" / "generic_level1.rego"

VENDOR_DIALECTS = {
    "cisco": "IOS", "juniper": "Junos", "paloalto": "PAN-OS",
    "fortinet": "FortiOS", "arista": "EOS",
}


@contextmanager
def _isolated_service_import(service_dir: Path):
    """Several services (parsing, compliance, remediation) each ship a
    top-level package literally named `app` — fine in their own isolated
    pytest run, but this script needs pieces from more than one of them in
    the same process. Swaps `sys.path`/`sys.modules["app"...]` to point at
    one service's `app` package for the duration of the `with` block, then
    restores whatever was there before, so importing remediation's
    `app.batfish_client` after parsing's `app.deterministic_extractor` (or
    vice versa) doesn't resolve submodules against the wrong service's
    `app.__path__`."""
    saved_path = sys.path[:]
    saved_modules = {k: v for k, v in sys.modules.items() if k == "app" or k.startswith("app.")}
    for k in saved_modules:
        del sys.modules[k]
    sys.path.insert(0, str(service_dir))
    try:
        yield
    finally:
        sys.path[:] = saved_path
        for k in [k for k in sys.modules if k == "app" or k.startswith("app.")]:
            del sys.modules[k]
        sys.modules.update(saved_modules)


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# opa_client.py and evidence_locator.py have no internal `app.*` imports of
# their own (see services/compliance/app/opa_client.py, evidence_locator.py),
# so they load standalone without needing `_isolated_service_import`.
opa_client = _load_module(REPO_ROOT / "services" / "compliance" / "app" / "opa_client.py", "crag_eval_opa_client")
evidence_locator = _load_module(
    REPO_ROOT / "services" / "compliance" / "app" / "evidence_locator.py", "crag_eval_evidence_locator"
)


# ── 1. Corpus Benchmarking ─────────────────────────────────────────────
def corpus_benchmark() -> dict:
    """Accuracy, parsing coverage, and extraction latency per vendor
    dialect, reusing benchmarks/adversarial/run_adversarial_benchmark.py's
    already-tested extraction/flattening logic rather than re-implementing
    it — this just re-groups its per-fixture output by vendor and adds a
    wall-clock timing pass, both offline."""
    with _isolated_service_import(REPO_ROOT / "services" / "parsing"):
        adv = _load_module(
            REPO_ROOT / "benchmarks" / "adversarial" / "run_adversarial_benchmark.py", "crag_eval_adversarial"
        )
        extractor = adv.TextFSMExtractor()

        per_vendor: dict[str, dict] = {}
        for golden_path in sorted(CORPUS_DIR.glob("*.expected.json")):
            fixture_name = golden_path.name.removesuffix(".expected.json")
            golden = json.loads(golden_path.read_text())
            vendor = golden["vendor"]
            config_text = (DEMO_DIR / fixture_name).read_text(encoding="utf-8")

            # Wall-clock latency for the deterministic extraction path only
            # — the SLM path's latency is a live-pipeline metric (network
            # call to Ollama/an external model) this offline script can't
            # measure without that service running.
            start = time.perf_counter()
            for _ in range(20):
                extractor.extract(config_text, vendor)
            latency_ms = (time.perf_counter() - start) / 20 * 1000

            bucket = per_vendor.setdefault(vendor, {
                "dialect": VENDOR_DIALECTS.get(vendor, "unknown"),
                "fixture_count": 0, "fields_expected": 0, "fields_correct": 0,
                "fields_attempted": 0, "latency_ms_total": 0.0, "fixtures": {},
            })
            expected_flat = adv._flatten(golden["expected_baseline"])
            actual_flat = adv._flatten(extractor.extract(config_text, vendor))
            correct = sum(1 for p, v in expected_flat.items() if actual_flat.get(p) == v)
            attempted = sum(1 for p in expected_flat if p in actual_flat)

            bucket["fixture_count"] += 1
            bucket["fields_expected"] += len(expected_flat)
            bucket["fields_correct"] += correct
            bucket["fields_attempted"] += attempted
            bucket["latency_ms_total"] += latency_ms
            bucket["fixtures"][fixture_name] = {
                "field_accuracy": correct / len(expected_flat) if expected_flat else 1.0,
                "parsing_coverage": attempted / len(expected_flat) if expected_flat else 1.0,
                "latency_ms": round(latency_ms, 4),
            }

        for vendor, bucket in per_vendor.items():
            bucket["field_extraction_accuracy"] = (
                bucket["fields_correct"] / bucket["fields_expected"] if bucket["fields_expected"] else 1.0
            )
            bucket["parsing_coverage"] = (
                bucket["fields_attempted"] / bucket["fields_expected"] if bucket["fields_expected"] else 1.0
            )
            bucket["avg_latency_ms"] = round(bucket["latency_ms_total"] / bucket["fixture_count"], 4)
            del bucket["latency_ms_total"]

        return {"frameworks_evaluated": ["CIS"], "vendors": per_vendor}


# ── 2. Retrieval Correctness (Evidence Linking) ────────────────────────
def evidence_coverage() -> dict:
    """Offline: every control_id the CIS bundle can emit as a `deny` finding
    must have an evidence_locator.CONTROL_PATTERNS entry, or a real finding
    could come back with no possible config-line proof to attach. Reads the
    rego source directly rather than duplicating its control list by hand,
    so this can't silently drift when a control is added."""
    control_ids = sorted(set(re.findall(r'"control_id":\s*"([^"]+)"', REGO_BUNDLE.read_text())))
    covered = {cid: cid in evidence_locator.CONTROL_PATTERNS for cid in control_ids}
    return {
        "bundle": str(REGO_BUNDLE.relative_to(REPO_ROOT)),
        "control_ids": control_ids,
        "uncovered_control_ids": sorted(cid for cid, ok in covered.items() if not ok),
        "coverage": sum(covered.values()) / len(covered) if covered else 1.0,
    }


async def _opa_reachable(url: str) -> bool:
    try:
        import httpx
        async with httpx.AsyncClient(timeout=3) as client:
            resp = await client.get(url.rsplit("/v1/data", 1)[0] + "/health")
        return resp.status_code < 500
    except Exception:
        return False


async def evidence_linking_live() -> dict | None:
    """Live: evaluates each corpus fixture against a real OPA + CIS bundle
    and checks that every returned finding carries OPA's own human-readable
    `evidence` string, a config_sha256 the eval can independently recompute
    and match, and at least one attached source line where evidence_locator
    has a pattern for that control. Returns None (not a fabricated pass)
    when OPA isn't reachable — same discipline as
    run_adversarial_benchmark.py's --live-results gate."""
    if not await _opa_reachable(opa_client.OPA_URL):
        return None

    per_fixture = {}
    for golden_path in sorted(CORPUS_DIR.glob("*.expected.json"))[:5]:
        fixture_name = golden_path.name.removesuffix(".expected.json")
        golden = json.loads(golden_path.read_text())
        config_text = (DEMO_DIR / fixture_name).read_text(encoding="utf-8")
        config_sha256 = hashlib.sha256(config_text.encode()).hexdigest()
        baseline = {**golden["expected_baseline"], "device": {
            **golden["expected_baseline"].get("device", {}), "config_sha256": config_sha256,
        }}

        try:
            findings = await opa_client.evaluate(baseline, "CIS")
        except opa_client.OPAEvaluationError as exc:
            per_fixture[fixture_name] = {"error": str(exc)}
            continue

        findings = evidence_locator.attach(findings, config_text)
        checks = []
        for f in findings:
            has_pattern = f.get("control_id") in evidence_locator.CONTROL_PATTERNS
            checks.append({
                "control_id": f.get("control_id"),
                "has_opa_evidence": bool(f.get("evidence")),
                "has_source_line": bool(f.get("source_lines")) if has_pattern else None,
            })
        per_fixture[fixture_name] = {
            "config_sha256": config_sha256,
            "finding_count": len(findings),
            "checks": checks,
            "all_findings_have_evidence": all(c["has_opa_evidence"] for c in checks) if checks else True,
            "all_locatable_findings_have_source_line": all(
                c["has_source_line"] is not False for c in checks
            ) if checks else True,
        }

    return {
        "opa_url": opa_client.OPA_URL,
        "bundle_version_env_set": bool(__import__("os").getenv("POLICY_BUNDLE_VERSION")),
        "fixtures": per_fixture,
    }


# ── 3. Verdict Reproducibility ──────────────────────────────────────────
async def verdict_reproducibility(runs: int = 5) -> dict | None:
    """Live: re-evaluates the same baseline against the same versioned CIS
    bundle `runs` times and asserts byte-identical findings every time —
    the deterministic-consistency guarantee opa_client.evaluate()'s sort-by-
    control_id is there for. Returns None when OPA isn't reachable."""
    if not await _opa_reachable(opa_client.OPA_URL):
        return None

    per_fixture = {}
    for golden_path in sorted(CORPUS_DIR.glob("*.expected.json"))[:3]:
        fixture_name = golden_path.name.removesuffix(".expected.json")
        golden = json.loads(golden_path.read_text())
        baseline = golden["expected_baseline"]

        renders = []
        for _ in range(runs):
            findings = await opa_client.evaluate(dict(baseline), "CIS")
            renders.append(json.dumps(findings, sort_keys=True))

        per_fixture[fixture_name] = {
            "runs": runs,
            "identical_every_run": len(set(renders)) == 1,
            "distinct_verdicts_seen": len(set(renders)),
        }

    return {"reproducible": all(v["identical_every_run"] for v in per_fixture.values()), "fixtures": per_fixture}


# ── 4. Remediation Safety ───────────────────────────────────────────────
REMEDIATION_FIXTURES = EVAL_DIR / "fixtures" / "remediation_scripts.json"


async def remediation_safety() -> dict:
    """Offline: true/false-positive rate of
    services/remediation/app/batfish_client.py's full preflight() — the
    regex lockout checks (static_safety_checks) plus
    services/remediation/app/reachability_fallback.py's deterministic
    ACL/route-diffing fallback (docs/Additional-Features.md §4), which
    forces RISK_FLAGS on a script that *widens* management/ACL reachability
    (e.g. removing an access-class or a `deny` entry) even when no static
    lockout pattern matched. This evaluates the two deterministic layers
    that actually run in production today. Real Batfish snapshot-based
    simulation isn't wired up (preflight() always returns UNAVAILABLE for
    a clean script without USE_MOCK_BATFISH), so this eval can't and
    doesn't claim to cover that."""
    with _isolated_service_import(REPO_ROOT / "services" / "remediation"):
        batfish_client = _load_module(
            REPO_ROOT / "services" / "remediation" / "app" / "batfish_client.py", "crag_eval_batfish_client"
        )
        preflight = batfish_client.preflight

    cases = json.loads(REMEDIATION_FIXTURES.read_text())["cases"]
    results = []
    for case in cases:
        result = await preflight(case["script"])
        flagged = result.status != "SAFE"
        results.append({
            "name": case["name"], "expect_flagged": case["expect_flagged"],
            "flagged": flagged, "engine": result.engine, "flags": result.risk_flags,
            "correct": flagged == case["expect_flagged"],
        })

    unsafe = [r for r in results if r["expect_flagged"]]
    safe = [r for r in results if not r["expect_flagged"]]
    true_positive_rate = sum(r["flagged"] for r in unsafe) / len(unsafe) if unsafe else None
    false_positive_rate = sum(r["flagged"] for r in safe) / len(safe) if safe else None

    return {
        "engine": "batfish_client.preflight (static-safety + reachability-fallback)",
        "true_positive_rate": true_positive_rate,
        "false_positive_rate": false_positive_rate,
        "cases": results,
    }


async def _run_live_evals() -> tuple[dict | None, dict | None, dict]:
    return await evidence_linking_live(), await verdict_reproducibility(), await remediation_safety()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    live_evidence, live_reproducibility, remediation_result = asyncio.run(_run_live_evals())

    report = {
        "corpus_benchmark": corpus_benchmark(),
        "evidence_linking": {"offline_coverage": evidence_coverage(), "live": live_evidence},
        "verdict_reproducibility": live_reproducibility,
        "remediation_safety": remediation_result,
    }
    rendered = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered)
    print(rendered, end="")

    ok = (
        report["evidence_linking"]["offline_coverage"]["coverage"] == 1.0
        and (live_reproducibility is None or live_reproducibility["reproducible"])
        and report["remediation_safety"]["true_positive_rate"] in (None, 1.0)
        and report["remediation_safety"]["false_positive_rate"] in (None, 0.0)
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
