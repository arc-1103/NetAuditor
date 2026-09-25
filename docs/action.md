# Action Plan — Items 6 & 7 (docs/Suggestions.md)

## Status (last updated 2026-09-25)

**Phases 1–3 are DONE, tested, and green.** Phase 4 (the adversarial
benchmark itself — the actual "item 6" deliverable) has **not been
started**. This is the next and only remaining work.

| Phase | Status | Evidence |
|---|---|---|
| 1 — Deterministic TextFSM extractor, all 5 vendors | ✅ Done | `services/parsing/app/deterministic_extractor.py` + `services/parsing/textfsm_templates/*.textfsm`; `services/parsing/tests/test_deterministic_extractor.py` (29 tests, validated against every real `demo/*.cfg` fixture) |
| 2 — Agreement scoring, `merge.py`/`worker.py` wiring, `parser_agreement` persisted, remediation's decision-table proxy swapped | ✅ Done | `services/parsing/app/agreement.py`; `audit_runs.parser_agreement` (migration 0009); `services/remediation/app/main.py`'s `_resolve_parser_agreement` (real signal, falls back to `parsing_confidence` when the vendor is uncovered) |
| 3 — Trust Layer view (`GET /api/audit-runs/{id}/trust`) | ✅ Done | `services/compliance/app/trust.py`; `audit_runs.deterministic_baseline` (migration 0010); gateway route wired and tested |
| 4 — Adversarial Configuration Benchmark (item 6 itself) | ❌ **Not started** | Nothing built yet — see "What Phase 4 still needs" below |

**Full test count as of this status, all passing:**
compliance 150, remediation 105, reporting 15 (logic/db; WeasyPrint-dependent
tests can't run on this Windows machine, pre-existing gap), gateway 35,
parsing 130+ (29 of them new this session). Nothing has been committed to
git — that's a deliberate hold, not an oversight.

### What Phase 4 still needs (do this next)

1. `benchmarks/adversarial/corpus/` — one `<fixture-name>.expected.json`
   golden `SecurityBaseline`-level label per existing `demo/*.cfg` fixture
   (16 files), for the fields each vendor's Phase 1 extractor covers. This
   is mechanical (read the fixture, write down what a correct parse
   returns) but has NOT been written yet — zero files exist in this
   directory today.
2. `benchmarks/adversarial/adversarial/` — new, hand-constructed fixtures
   for the four test classes docs/Suggestions.md §6 names (Normal,
   Ambiguous, Malformed, Adversarial) — see this doc's Phase 4 section
   above for what each class means and an example of the "adversarial"
   trap (a commented-out `no telnet` beside an active `telnet` enable).
   None of these fixtures exist yet.
3. `benchmarks/adversarial/run_adversarial_benchmark.py` — drives every
   corpus fixture through Parsing (SLM + the now-working deterministic
   extractor) and Compliance (OPA), scores: parser disagreement (already
   computable via `app/agreement.py`), extraction accuracy (vs. the golden
   corpus from step 1), schema rejection rate, policy-result deviation,
   human-review rate. Not started.
4. `benchmarks/adversarial/README.md` — states the corpus-scope caveat
   (synthetic demo fixtures, not an independently-reviewed real-world
   corpus — see this doc's "What this plan does NOT attempt" section).
   Not started.
5. False acceptance rate / "Unsafe Action Escape Rate" need the full
   parse→compliance→remediation→decision pipeline run per adversarial
   fixture — scaffold the hook in step 3's script but expect the real
   numbers to land in a follow-up pass, per this doc's original Phase 4
   note.

### Known follow-ups noted during Phases 1–3 (not blockers, just flagged)

- `services/parsing/app/vendor_detector.py` has no regex pattern for
  `fortinet` at all (only cisco/juniper/paloalto/arista) — the Fortinet
  TextFSM templates this session built are real and tested, but a real
  Fortinet config would currently be auto-detected as `"unknown"` vendor
  before ever reaching the deterministic extractor's `"fortinet"` builder.
  Not something this plan's scope covers fixing; worth a one-line
  regex-pattern addition to `vendor_detector.py` in a future pass if
  Fortinet cross-checking needs to work end-to-end, not just via an
  explicitly-supplied vendor string (as the unit tests do).
- SNMP version for Fortinet/Juniper community-string config is an
  approximation (`"v2c"` default when only a community string is seen, no
  explicit version discriminator in those vendors' config syntax) — flagged
  inline in `deterministic_extractor.py`'s comments at each occurrence.
- `infra/postgres/init.sql` was already missing `mean_logprob`/
  `reverse_translation_fidelity`/`credential_evidence` before this session
  (those columns exist only via migrations 0001/0004/0005, never backfilled
  into the fresh-install bootstrap file) — a pre-existing gap, not
  introduced or fixed by this work. This session's own new columns
  (`parser_agreement`, `deterministic_baseline`, and everything from the
  Additional-Features.md pass) were all added to both the migration AND
  `init.sql`, so they don't carry the same gap forward.

---

## Scope

This plan covers:
- **Item 6 — Adversarial Configuration Benchmark**
- **Item 7 — AI Interpretation Trust Layer**

Both depend on the same missing piece: an **independent, deterministic
second parser** to cross-check the SLM's extraction against. Today,
`services/parsing` has exactly one extraction path (the SLM, `app/worker.py`)
and zero TextFSM/regex-based deterministic extraction — every reference to
"TextFSM cross-check" in this repo (`docs/ArchitecturalChanges.md` §3/§5,
`services/remediation/policy/decision_table.yaml`'s `parser_agreement`
header comment) describes it as **not yet built**. So item 7's build *is*
building that cross-check; item 6's benchmark is built on top of it.

This plan builds both from zero, in the order below, each phase leaving a
working, tested state.

---

## What this plan does NOT attempt, and why

One thing `docs/ArchitecturalChanges.md` describes is **human-judgment
work**, not code, and stays out of this plan:

**A real-world, independently-reviewed labeled corpus.**
`docs/ArchitecturalChanges.md` §5 scopes "corpus labelling against
CIS/STIG/NIST ground truth" at **2 people, dedicated, weeks 1–12** — it
requires a human who can look at a real (or realistically messy) config
and say what a compliant interpretation of it actually is. I can't
manufacture that judgment. What this plan *does* do instead (Phase 2) is
build a golden corpus from the repo's existing 16 `demo/*.cfg` fixtures,
which I can label correctly myself because they're purpose-built synthetic
configs with a known-by-construction intent (a "hardened" vs. "insecure"
pair, already scored at the compliance-finding level by
`demo/expected-findings.json`) — reading the raw CLI text and stating what
`SecurityBaseline` fields it implies is a mechanical reading task here, not
a judgment call about an ambiguous real device. This is explicitly a
**smaller, narrower claim** than "a reviewed real-world corpus" and the
benchmark's own README says so, the same way `benchmarks/README.md`
already caveats the 3-fixture demo today.

### Vendor and field coverage — confirmed at full scope

Explicitly decided (not a default): the deterministic cross-check covers
**all 5 vendors with existing demo fixtures** (`cisco`, `fortinet`,
`juniper`, `paloalto`, `arista` — matching `vendor_detector.py`'s existing
regex detection and the `demo/*.cfg` hardened/insecure pairs) across
**all 13 `SecurityBaseline` sections** (`ssh`, `telnet`, `snmp`, `acl`,
`crypto`, `ntp`, `aaa`, `banners`, `logging`, `services`,
`interfaces`/`topology`, `device`), not just the fields the current
11-control CIS Level-1 Rego bundle happens to read. This directly matches
item 7's own mockup, which cross-checks `hostname` — a device-identity
field with no compliance-gating role at all — so the trust layer is meant
to be a general parsed-baseline view, not a compliance-verdict-only signal.

A vendor/field this parser doesn't yet cover is still a "no signal"
abstention, never a wrong answer, and never penalizes confidence or blocks
anything — same fail-open posture the rest of this codebase uses. At this
scope, real coverage gaps are expected on the first pass (five vendors'
worth of CLI syntax across ACL/interface/routing-neighbor list structures
is genuinely large); Phase 1 below sequences vendors and sections so each
slice lands tested rather than attempting all 5×13 combinations in one
untested block.

---

## Phase 1 — Deterministic cross-check parser (foundation for both items)

**New module:** `services/parsing/app/deterministic_extractor.py`

- A `TextFSMExtractor` class wrapping the `textfsm` PyPI package (new
  dependency — confirmed absent from `requirements.txt` today) with one
  `.textfsm` template per (vendor, section-group) pair, under a new
  `services/parsing/textfsm_templates/` directory. Built and landed
  vendor-by-vendor, not all 5×13 at once:
  1. `cisco` — the reference implementation, built first since
     `demo/cisco_*.cfg` has the most fixtures (7) to validate against.
  2. `fortinet`, then `juniper`, `paloalto`, `arista` — each added once
     `cisco`'s pattern (template structure, list-field handling, test
     shape) is proven, reusing that structure rather than re-deriving it.
  Within each vendor, group sections by structural shape rather than
  one-template-per-section: simple scalar/flag sections (`ssh`, `telnet`,
  `snmp`, `ntp`, `aaa`, `banners`, `logging`, `services`, `device` identity)
  fit one combined per-vendor TextFSM template (`Value` per field, one
  `Record` per config); list-of-records sections (`acl.ingress_entries`/
  `egress_entries`, `crypto.ike_policies`, `interfaces`, `routing_neighbors`)
  need their own template per vendor since TextFSM's `Record` action fires
  per matched row, which is exactly list-extraction shape. Regex-based
  `re.search` extraction (matching `vendor_detector.py`'s existing style)
  is the fallback for fields TextFSM's line-template matching doesn't fit
  well (e.g. simple presence checks like `banners.login_banner_present`).
- Follows the exact DI pattern `worker.py` already uses for `RAGContextProvider`/
  `VendorFingerprintProvider`: a `Protocol` (`DeterministicExtractorProvider`),
  a real implementation, an `EmptyDeterministicExtractorProvider` (returns
  "no signal" for every field — the safe default for an unsupported vendor),
  injected into `_parse_chunk`/`_process_config` as an optional keyword arg.
- Output shape: a partial `SecurityBaseline`-shaped dict containing **only**
  the fields it actually extracted (unset fields are absent, not defaulted
  — absence must mean "no signal," matching every other optional signal in
  this pipeline).
- New env vars in `app/config.py`, same frozen-dataclass pattern as every
  existing setting: `ENABLE_DETERMINISTIC_CROSSCHECK` (default `true`),
  `TEXTFSM_TEMPLATE_DIR`.

**Tests:** `services/parsing/tests/test_deterministic_extractor.py` — one
`.textfsm` template's extraction verified per test, inline config-text
fixtures (matching the existing house style — no fixture files on disk),
plus an explicit "unsupported vendor returns no signal, never a wrong
value" test.

---

## Phase 2 — Agreement scoring + merge integration (item 7's core signal)

**New module:** `services/parsing/app/agreement.py`

- `compute_agreement(slm_baseline: dict, deterministic_partial: dict) -> AgreementResult`
  — for every field the deterministic extractor actually returned a value
  for (its partial-dict keys only — never penalizes fields it abstained
  on), compare against the SLM's value for that same field. Reuses
  `reverse_translation.py`'s existing `_leaf_facts()` flattening approach
  (already does exactly this "compare two SecurityBaseline-shaped
  structures fact-by-fact" job) rather than writing a second diffing
  algorithm.
- Returns per-field results (`agree: bool`, `slm_value`, `deterministic_value`)
  plus an aggregate `agreement: float` (0..1, fraction of *compared* fields
  that matched — fields TextFSM abstained on aren't in the denominator) and
  `disagreements: list[str]` (dotted field paths, same shape as
  `merge.py`'s existing `conflicts` list).
- **Wired into `merge.py`**: `worker.py`'s existing `conflicts` list already
  flows through to the job result payload and already costs a confidence
  penalty (`worker.py:347-348`) for same-SLM chunk disagreement.
  Deterministic-vs-SLM disagreements are added to that *same* list
  (distinguishable by a `deterministic:` prefix on the field path) rather
  than inventing a parallel mechanism — one disagreement concept, two
  sources.
- **`worker.py` job result gets a new field**: `parser_agreement: float | None`
  — `None` when the deterministic extractor abstained on every field for
  this job (unsupported vendor), never `1.0`/`0.0` by default. This is
  deliberately a *new, additional* field, not a silent redefinition of
  `parsing_confidence` — the two stay distinct signals (SLM's own
  self-reported confidence vs. independent-parser agreement), matching
  `docs/Additional-Features.md` §2's own distinction between them.
- **New Postgres column**: `audit_runs.parser_agreement DOUBLE PRECISION`
  (migration `0009_add_parser_agreement.sql`), written by
  `services/compliance/app/db.py:save_findings` alongside the existing
  `parsing_confidence`/`mean_logprob` columns (same pattern).

**The actual payoff — swap the proxy**: `services/remediation/app/db.py`'s
`get_run_parsing_confidence()` (its own docstring already names this as the
swap point) gets a sibling `get_run_parser_agreement()`, and
`services/remediation/app/decision.py`'s `decide()` call in `app/main.py`
switches from `parsing_confidence` to `parser_agreement` — falling back to
`parsing_confidence` when `parser_agreement is None` (unsupported vendor),
so the decision table degrades to today's behavior rather than blocking
every non-Cisco/Fortinet device. `decision_table.yaml`'s header comment
gets updated to record that the swap happened and what `None` means now.

**Tests:** `test_agreement.py` (pure function, agreement math + abstention
handling), plus `test_merge.py`/`test_worker.py` updates for the new
`conflicts` entries and `parser_agreement` job field,
`services/remediation/tests/test_decision.py` updates for the fallback
behavior.

---

## Phase 3 — Trust Layer surfacing (item 7's UI-facing half)

**New endpoint:** `GET /audit-runs/{id}/trust` (compliance service) —
returns, per scoped field, exactly the shape `docs/Suggestions.md` §7
mockup shows: `{field, slm_value, deterministic_value, source: "SLM"|"TextFSM"|"agreement", agreement_pct, evidence (source_lines), confidence, authority}`.
Composed from data Phase 1/2 already persisted (`audit_runs.parser_agreement`,
the `deterministic:`-prefixed entries in `conflicts`, existing
`source_lines` evidence) — no new computation, a read/reshape endpoint
matching the style of the `/provenance` endpoint I already built for
Additional-Features.md §6.

**Gateway route:** `GET /api/audit-runs/{id}/trust`, `require_reader`.

---

## Phase 4 — Adversarial Configuration Benchmark (item 6)

**New directory:** `benchmarks/adversarial/` (sibling to the existing
`benchmarks/`), containing:

- `corpus/` — the golden `SecurityBaseline`-level labels for the 16
  existing `demo/*.cfg` fixtures (see the corpus-scope caveat above),
  one `<fixture-name>.expected.json` per config, covering every field
  Phase 1's extractor targets for that fixture's vendor (full schema,
  per the confirmed scope) — landed fixture-by-fixture alongside each
  vendor's TextFSM templates in Phase 1, not as a separate pass.
- `adversarial/` — new, deliberately-constructed synthetic fixtures for
  the four test classes `docs/Suggestions.md` §6 names:
  - **Normal** — reuse existing `demo/*_hardened.cfg`/`*_insecure.cfg`,
    expect clean parse + no disagreement.
  - **Ambiguous** — a config with a genuinely double-meaning directive
    (e.g. a comment that contradicts the active config line it
    annotates), expect `human_review` (low `parsing_confidence` or
    nonzero `parser_agreement` disagreement).
  - **Malformed** — truncated/corrupted config text, expect `schema_validator`
    rejection.
  - **Adversarial** — a config engineered to look compliant to a naive
    regex/keyword scan while actually being insecure (or vice versa) —
    e.g. a commented-out `no telnet` beside an active `telnet` enable,
    designed so the *right* answer is unambiguous on careful reading even
    though a shallow parser could be fooled — expect rejection/escalation,
    never a silent pass.
  Each is constructible and verifiable here (I know the intended trap and
  the correct answer by construction), unlike a real adversarial
  real-world config, which would need the same human review as item 1's
  corpus.
- `run_adversarial_benchmark.py` — drives every corpus fixture through
  `services/parsing` (SLM + deterministic extractor) and
  `services/compliance` (OPA), scoring the metrics `docs/Suggestions.md`
  §6 names that are actually computable from what Phases 1–3 produce:
  **parser disagreement** (Phase 2's `agreement`), **extraction accuracy**
  (against the golden corpus), **schema rejection rate**, **policy-result
  deviation** (compliance verdict vs. golden), **human-review rate**. Two
  metrics from the doc's list — **false acceptance rate** and **unsafe-remediation
  rate** (its "Unsafe Action Escape Rate")  — need the full
  parse→compliance→remediation→decision pipeline wired end-to-end per
  fixture; scaffold the hook for them in this script but they depend on
  Phases 1–3 landing first, so their numbers come from a follow-up pass,
  not this one.
- `README.md` — states the corpus-scope and coverage-scope caveats from
  this plan's "What this plan does NOT attempt" section up front, the same
  way `benchmarks/README.md` already does for the existing 3-fixture demo.

---

## Sequencing

Phase 1 → 2 → 3 → 4, in that order — each phase's tests must pass before
the next starts, matching how the rest of this session's work was done
(migration + code + tests, one slice at a time, not everything at once).
Phase 4 is the actual "item 6" deliverable and is the most work; Phases
1–3 are its prerequisite (and are "item 7" in their own right).
