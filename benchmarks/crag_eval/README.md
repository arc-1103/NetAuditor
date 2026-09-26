# CRAG Evaluation Framework

Evaluates the specialized CRAG setup's two halves — the deterministic/SLM
extraction step and the OPA policy-verdict step — across the four categories
a benchmark for this pipeline needs. Same "no benchmark number is committed"
discipline as `benchmarks/adversarial/`: every metric is computed from real,
checkable output, and anything this script can't actually check is reported
as `null`/"unavailable", never fabricated.

## What's here

- `run_crag_eval.py` — the harness. Four sections, one per eval category:
  1. **Corpus Benchmarking** — field-extraction accuracy, parsing coverage,
     and per-fixture extraction latency, grouped by vendor dialect (IOS,
     Junos, PAN-OS, FortiOS, EOS), against
     `benchmarks/adversarial/corpus/*.expected.json`. Fully offline — reuses
     `run_adversarial_benchmark.py`'s already-tested extraction/flattening
     logic rather than re-implementing it.
  2. **Retrieval Correctness (Evidence Linking)** — offline: every
     `control_id` `services/compliance/policies/generic/generic_level1.rego`
     can emit has an `evidence_locator.CONTROL_PATTERNS` entry, so no finding
     can come back with no possible config-line proof. Live (needs OPA):
     evaluates each corpus fixture through the real bundle and checks every
     finding carries OPA's own `evidence` string, an attached source line
     where one is locatable, and a config_sha256 the eval independently
     recomputes and matches.
  3. **Verdict Reproducibility** — live only: re-evaluates the same baseline
     against the same versioned bundle 5 times and asserts byte-identical
     findings every run.
  4. **Remediation Safety** — offline: true-positive/false-positive rate of
     `services/remediation/app/batfish_client.py`'s `static_safety_checks()`
     against `fixtures/remediation_scripts.json`'s 6 known-unsafe and 6
     known-safe remediation scripts (one case per regex category the
     function checks, hand-verified against the real function output).
- `fixtures/remediation_scripts.json` — the remediation-safety cases above.
- `test_run_crag_eval.py` — unit tests for the offline sections.
- Three new golden fixtures added to `benchmarks/adversarial/corpus/` +
  `demo/` to close single-control-isolation gaps that only Cisco had before
  (`cisco_telnet_only.cfg`, `cisco_snmp_only.cfg`, `cisco_weak_crypto.cfg`):
  `juniper_telnet_only.conf`, `arista_snmp_only.cfg`,
  `paloalto_weak_crypto.conf`. Each was verified by running the real
  `TextFSMExtractor` against it before its `.expected.json` was written.

## Running it

```bash
pip install textfsm httpx   # services/parsing and services/compliance deps
python benchmarks/crag_eval/run_crag_eval.py
```

The offline sections (corpus benchmark, evidence coverage, remediation
safety) always run and score 100%/0% against the fixtures here. The two
live sections (evidence-linking's live check, verdict reproducibility) need
a reachable OPA loaded with `services/compliance/policies` — run
`docker compose up opa` and either add a host port mapping or point
`OPA_URL` at wherever it's reachable, e.g.:

```bash
OPA_URL=http://localhost:8181/v1/data python benchmarks/crag_eval/run_crag_eval.py
```

Without that, both report `null` rather than a fabricated pass — the same
"unavailable, not invented" rule `benchmarks/adversarial/run_adversarial_benchmark.py`
already follows for its own live-pipeline-only metrics.

## Scope caveats — read before quoting these numbers anywhere

- **CIS only.** NIST and STIG have no Rego bundle yet — only
  `services/compliance/policies/generic/generic_level1.rego` (CIS,
  "illustrative subset," 11 controls) exists. `services/compliance/app/opa_client.py`
  raises for those frameworks today, so this eval never references them.
  Extend this suite once NIST/STIG bundles land, following the same
  offline-coverage + live-verdict pattern used here for CIS.
- **Remediation safety evaluates the static-check layer, not real Batfish.**
  `batfish_client.py`'s own module docstring is explicit: a real Batfish
  deployment needs an operator-supplied topology/snapshot that isn't wired
  up, and the client returns `UNAVAILABLE` rather than claiming an
  unvalidated change is safe. `docker-compose.yml` does have a
  `batfish/allinone` service (under the `advanced` profile), but running it
  only proves the coordinator is reachable — building the snapshot/topology
  ingestion and differential-reachability questions a real pre-flight
  simulation needs is a separate feature, not eval work, and isn't attempted
  here. Treat this eval's TP/FP rate as "does the static regex layer catch
  the lockout patterns it's designed for," not "does the system detect every
  way a change could cause an outage."
- **The corpus is small and purpose-built, not independently reviewed.**
  Same caveat `benchmarks/adversarial/README.md` already states for its own
  corpus: every fixture here is a synthetic config with a known-by-construction
  intent, not a real device config labeled against CIS/STIG/NIST ground
  truth by an independent reviewer. 100% accuracy here means "correct on the
  cases we thought to construct."
- **Latency is a microbenchmark of the deterministic extractor only.** It
  does not include the SLM path (a network call to Ollama or another model),
  OPA evaluation, or any other pipeline stage — those need a live pipeline
  run to measure and aren't captured by this offline script.
