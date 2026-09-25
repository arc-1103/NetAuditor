# Adversarial Configuration Benchmark

Implements `docs/Suggestions.md` §6 (item 6) and backs the AI Interpretation
Trust Layer (§7, item 7) with a real, independent cross-check signal. See
`docs/action.md` Phase 4 for the build plan this benchmark came from.

## What's here

- `corpus/` — one `<fixture-name>.expected.json` golden `SecurityBaseline`
  label per existing `demo/*.cfg`/`*.conf` fixture, covering every field
  each vendor's `services/parsing/app/deterministic_extractor.py` targets.
- `adversarial/` — hand-constructed fixtures for the four test classes
  `docs/Suggestions.md` §6 names:
  - **Normal** — already covered by the `demo/*_hardened.cfg`/`*_insecure.cfg`
    pairs scored via `corpus/`; no separate fixture needed here.
  - **Ambiguous** — `ambiguous_conflicting_vty_ranges.cfg`: two vty ranges
    with genuinely different transport-input policies that a single scalar
    field can't represent without loss.
  - **Malformed** — `malformed_truncated.cfg`: truncated/corrupted config
    text, expected to fail schema validation.
  - **Adversarial** — `adversarial_disguised_telnet.cfg`: an active `telnet`
    enable disguised next to a commented-out `no telnet`, engineered to fool
    a shallow keyword scan.
- `run_adversarial_benchmark.py` — scores what's checkable offline every run
  (extraction accuracy and vendor-detection accuracy against `corpus/`,
  whether each `adversarial/` fixture's deterministic-extractor output still
  matches its own `.expected.json`) and reports the metrics that need a real
  Parsing+Compliance pipeline run (parser disagreement, schema rejection
  rate, policy-result deviation, human-review rate) as `null` unless
  `--live-results <dir>` points at captured `<fixture>.json` audit-run
  responses, in the same shape `benchmarks/score_demo_results.py` expects.

## Running it

```bash
pip install textfsm   # services/parsing/requirements.txt dependency
python benchmarks/adversarial/run_adversarial_benchmark.py
```

Add `--live-results benchmark-results --output benchmark-results/adversarial-metrics.json`
once you have captured real pipeline responses to also score the
live-pipeline-only metrics.

## Scope caveats — read before quoting these numbers anywhere

- **Not an independently-reviewed real-world corpus.** Every fixture here is
  a purpose-built synthetic config with a known-by-construction intent, not
  a real device config a human has labeled against CIS/STIG/NIST ground
  truth. `docs/ArchitecturalChanges.md` §5 scopes that labeling effort at
  2 dedicated people over weeks 1–12 — it isn't something this benchmark can
  substitute for. Treat 100% accuracy here as "the extractor is correct on
  the cases we thought to construct," the same way `benchmarks/README.md`
  already caveats its own three-fixture demo.
- **False acceptance rate and Unsafe Action Escape Rate are not computed by
  this script.** Both need the full parse → compliance → remediation →
  decision pipeline wired end-to-end per fixture. `score_live_results()` has
  a hook for them but returns `null` until a follow-up pass extends the
  captured-result shape to carry Compliance's verdict and Remediation's
  decision alongside Parsing's output.
- **Coverage matches, not exceeds, `services/parsing/app/vendor_detector.py`.**
  A vendor/field the deterministic extractor doesn't cover is a "no signal"
  abstention in every metric here, never scored as a wrong answer.
