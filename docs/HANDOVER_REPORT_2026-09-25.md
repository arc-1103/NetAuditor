# NetAudit Engine — Handover Report (2026-09-25)

**Scope of this report:** (1) what infra was added this session (nginx), (2)
a full audit of every markdown doc in the repo — 44 files — covering what's
current, what's stale, what's duplicated, and what's pure scratch, (3) a
consolidated picture of the final architecture and how the code actually
works today, (4) what's built vs. scoped-but-not-built vs. out of scope
against `docs/Suggestions.md`'s roadmap, and (5) a recommended final
markdown file set for the repo.

This supersedes `docs/PRESENTATION_CLAIMS_CHECKLIST.md`'s vendor/benchmark
numbers and extends `docs/action.md`/`docs/ArchitecturalChanges.md` as the
most current status source. It does **not** supersede
`docs/HANDOVER_REPORT_2026-09-09.md` or `docs/report.md` — those stay as
historical session records; this report picks up where they left off.

§6.3's four duplicate-file deletions (and the two inaccurate checkboxes
they depended on fixing first) have been executed — see the updated §6.3.
Everything else in §6 (the consolidation merges) is still a proposal, not
a changelog — those need their own go-ahead before anything is merged.

---

## 1. What NetAudit Engine is

One-line thesis (from `docs/Suggestions.md` §13, now the working thesis
across the newer docs too):

> AI interprets configurations and proposes remediation. Deterministic
> policy, evidence provenance, network simulation, and authorization
> controls — not the AI — determine whether any action can proceed.

*"The model parses; the policy decides."*

---

## 2. Final architecture — services and how the code works

### 2.1 Service map

| Service | Responsibility | Key files |
|---|---|---|
| `services/ingestion` | Upload intake: MIME/size validation (`python-magic`), credential redaction, SHA-256 hash, write to MinIO (`raw-configs` bucket), dispatch a Celery job | `app/main.py`, `app/uploader.py` |
| `services/parsing` | Config → `SecurityBaseline`. Two extraction paths run in parallel: an SLM (Ollama) call and a deterministic TextFSM extractor (5 vendors); agreement between them feeds `parser_agreement` | `app/worker.py`, `app/deterministic_extractor.py`, `app/agreement.py`, `app/slm_client.py` — **Celery worker only, no HTTP surface today** (see §4.2) |
| `services/compliance` | Evaluates a `SecurityBaseline` against the OPA policy bundle (`policies/generic/generic_level1.rego` — vendor-agnostic, not per-vendor files), scores findings, computes GraphRAG blast radius (Neo4j), runs anomaly detection, serves the Trust Layer and Counterfactual endpoints | `app/evaluator.py`, `app/opa_client.py`, `app/counterfactual.py`, `app/reachability_diff.py`, `app/trust.py` |
| `services/remediation` | Renders a fix (Jinja2 template for Cisco/Fortinet, agentic-RAG synthesis for everything else), classifies it via the confidence-weighted decision table, gates approval through RBAC + the AI-actor firewall, records apply/rollback | `app/decision.py`, `app/approval_matrix.py`, `app/rag_remediation.py`, `policy/decision_table.yaml` |
| `services/reporting` | PDF/JSON/CEF report generation, MTTR, fleet score, full policy-provenance chain | `app/db.py` (`get_provenance_chain`) |
| `services/learning` | Human-in-the-loop mapping for unknown fields, embedding/RAG store (ChromaDB), vendor fingerprinting, remediation-manual and anomaly peer corpus | `backend/app/*.py` |
| `gateway` | Single external API surface, JWT auth, proxies every `/api/*` route to the internal services | `app/main.py`, `app/auth.py` |
| `frontend` | Next.js dashboard | `src/app/*` |

### 2.2 Request flow (happy path)

```
Upload (gateway -> ingestion)
  -> redact + hash + store in MinIO -> Celery job queued
Parsing (async worker)
  -> SLM extraction + deterministic TextFSM extraction, in parallel
  -> agreement scored -> SecurityBaseline persisted, parser_agreement stored
  -> Celery hands off to Compliance
Compliance (async worker)
  -> OPA evaluates the generic policy bundle -> findings
  -> GraphRAG blast radius (Neo4j) + anomaly check (ChromaDB) attached
  -> compliance_findings persisted (current-state, not append-only —
     re-running a run replaces its rows; audit_runs is the immutable trail)
Remediation (on demand, gateway -> remediation)
  -> template render (cisco/fortinet) or agentic-RAG synthesis (other vendors)
  -> decide() classifies: BLOCK / DUAL_APPROVAL / SINGLE_APPROVAL / AUTO_APPLY
     (inputs: parser_agreement, blast_radius_count, severity->risk)
  -> approval_matrix.check_permission(): RBAC + actor_type=="human" required
     (an AI/automation caller can never itself be the approval)
  -> apply/rollback only ever *record* that a human ran a script by hand —
     there is no live device-push path in this codebase
Reporting (on demand)
  -> renders findings/remediation/events into PDF/JSON/CEF + provenance chain
```

### 2.3 Infra

| Component | Role | Status |
|---|---|---|
| Postgres | System of record — `audit_runs`, `compliance_findings`, `remediation_proposals`, ledger tables | Stable, 10 migrations applied on top of `init.sql` |
| Redis | Celery broker | Stable |
| MinIO | Raw config object store, `raw-configs` bucket | Bucket created lazily by `services/ingestion/app/uploader.py` — no infra-side bootstrap needed; `infra/minio/` removed this session (nothing else lives there — the folder wasn't even bind-mounted) |
| Neo4j | GraphRAG topology graph for blast-radius traversal | Stable |
| ChromaDB | Vector store for Learning's RAG corpora | Stable |
| OPA | Policy evaluation server | Stable, pinned to `1.20.2` |
| Ollama | SLM inference (`qwen2.5:7b-instruct-q4_K_M` default) | Stable; `infra/ollama/` is correctly a gitignored runtime cache for pulled model blobs — removed this session's proposed `Modelfile` idea since nothing in the compose bootstrap (`ollama-bootstrap`, a plain `ollama pull`) actually consumes one |
| **nginx** | **TLS terminator + reverse proxy, `/` -> frontend:3000, `/api/` -> gateway:8000** | **Added this session** — was a documented "demo-day blocker" (`docs/report.md` §4.4 item 1: no compose service, `infra/nginx/` empty despite `NGINX_PORT=443` being defined). Now: `infra/nginx/{nginx.conf,generate-cert.sh,Dockerfile}` + a new `nginx` compose service, self-signed cert generated idempotently on first boot (no real domain to get a CA cert for in this context) |
| Batfish | Static preflight risk-flag check on a remediation script | Stable |

---

## 3. What's built vs. scoped-but-not-built vs. out of scope

Against `docs/Suggestions.md`'s 11-item roadmap (P0/P1/P2):

| # | Item | Status |
|---|---|---|
| 1 | AI Authorization / Agent Firewall | **Built.** `decide()` classifies every proposal; `approval_matrix.check_permission()` + the `actor_type` header check (added this session) hard-block an AI/automation caller from ever being the approval. `simulation_required`/`SAFE\|BLOCK\|HUMAN_APPROVAL` vocabulary labels were scoped but **not built** — see §4.1. |
| 2 | Blast-Radius Analysis | **Built.** Two layers: GraphRAG live topology traversal (current-state, per finding) and `reachability_diff.diff_topology()` (before/after interface/route counts, added this session), both feeding `counterfactual()`. |
| 3 | Counterfactual Compliance Engine | **Built**, caller-supplies-both-baselines shape. `POST /counterfactual` (compliance) scores a proposed baseline against the current one — ACL reachability, topology blast radius, compliance delta, risk tier, verdict. **Not built:** auto-synthesizing the proposed baseline from a remediation script's raw CLI text — see §4.1, this was scoped in detail this session and deliberately not started once the real size of the prerequisite work (a new sync HTTP surface on `services/parsing`, which today is Celery-only) became clear. |
| 4 | Policy-to-Rego Compiler | **Not started.** |
| 5 | Policy Provenance Graph | **Built.** `reporting.get_provenance_chain()` returns policy/finding/remediation/events per control, `rule_id` made explicit this session. |
| 6 | Adversarial Configuration Benchmark | **Built.** `benchmarks/adversarial/` — 17 golden fixtures, 3 adversarial classes, `run_adversarial_benchmark.py`. `policy_result_deviation` and `unsafe_action_escape_rate` metrics filled in this session — **`benchmarks/adversarial/README.md` is now stale on this point** (still says they return `null`, see §6). False-acceptance rate remains genuinely unavailable (no negative-class ground truth in a 3-fixture set). |
| 7 | AI Interpretation Trust Layer | **Built.** `GET /audit-runs/{id}/trust` — per-field SLM-vs-TextFSM agreement, evidence, confidence. |
| 8 | Compliance Drift | **Not started.** |
| 9 | Compliance Digital Twin | **Not started** — `Suggestions.md` itself scopes this as longer-term, non-mandatory. |
| 10 | Combined architecture | Substantially matches §2.2's flow above already, short of the auto-simulation loop in item 3. |
| 11 | Priority roadmap | This table is its current status. |

### 3.1 Vendor / framework coverage (verified this session, corrects stale doc claims)

- **Parsing (deterministic cross-check):** 5 vendors — cisco, fortinet, juniper, paloalto, arista.
- **Compliance (OPA policy):** vendor-agnostic — `policies/generic/generic_level1.rego`, one bundle, not per-vendor files. This is a real architectural change from the original Cisco-only bundle `docs/report.md` describes; several docs (`compliance/README.md`'s "known gaps" section, `PRESENTATION_CLAIMS_CHECKLIST.md`) haven't caught up to this.
- **Remediation (template rendering):** Cisco (`ios_*.j2`) + Fortinet (`fortinet_*.j2`) only, 19 templates. Juniper/PaloAlto/Arista fall back to agentic-RAG synthesis (forced un-approvable, manual-verification-only — see `AGENTIC_RAG_MANUAL_VERIFICATION_FLAG` in `services/remediation/app/main.py`).
- **Frameworks:** only CIS-style Level 1 is implemented. NIST/STIG are accepted as framework names but have no policy files — a request 502s rather than silently returning "compliant."

---

## 4. What was scoped this session but explicitly not built

### 4.1 Full counterfactual auto-invocation from remediation

The deepest piece of scoping this session did. The chain: wiring item 1's
authorization decision to actually call item 2/3's simulation engine before
classifying a proposal, instead of trusting a pre-supplied blast-radius
count, requires reconstructing a *proposed* `SecurityBaseline` from a
remediation script's raw CLI text. That in turn requires:

- Raw config text to be available somewhere by `audit_run_id` — **it isn't,
  anywhere in this codebase today.** `audit_runs.storage_path` points at
  MinIO but nothing reads it back; the only persisted raw text is
  `learning_queue.raw_text`, scoped to individual failed chunks, not full
  configs.
- A synchronous parse endpoint on `services/parsing` — **doesn't exist.**
  Parsing has zero HTTP surface today, only the Celery worker. The
  underlying extraction logic (`TextFSMExtractor.extract()`) is a pure,
  dependency-free function and could back a new `POST /parse` endpoint, but
  that endpoint itself needs building (new `app/main.py`, `fastapi`/
  `uvicorn` added to requirements, a Dockerfile split into API + worker
  containers mirroring the existing `compliance`/`compliance-worker` pair).

The scoped, not-yet-executed plan (confirmed with the user as the
"caller-supplied text, no schema change" path — matching the pattern
`counterfactual.py`/`reachability_diff.py` already use, where the caller
supplies both before/after sides rather than the service looking anything
up): add an optional `current_config_text` field to remediation's
`GenerateRequest`; when supplied, call the new parsing endpoint twice
(current text alone, then current text + remediation script) to get both
baselines, then call compliance's existing, unchanged `/counterfactual`.
Falls back to today's behavior exactly when the field is omitted.

**Whoever picks this up next**: the design work is done (this section +
the session transcript), the implementation isn't. Start with the parsing
sync endpoint — it's independently testable before touching remediation.

### 4.2 `simulation_required` / `SAFE|BLOCK|HUMAN_APPROVAL` verdict labels

Scoped alongside §4.1 as a smaller, independent piece: add
`simulation_required: bool` to `decide()`'s output (true when risk is HIGH
or blast radius crosses a threshold) and a `verdict` field mapping the
existing action tiers to `Suggestions.md`'s own vocabulary
(`AUTO_APPLY`->`SAFE`, `BLOCK`->`BLOCK`, `SINGLE_APPROVAL`/`DUAL_APPROVAL`->
`HUMAN_APPROVAL`). Not built — got folded into the larger §4.1 scoping
before either landed.

---

## 5. Out of scope (explicit)

Per `Suggestions.md` §12, restated because it still holds: novelty claims
like "we use Qwen" / "we use Batfish" / "we support many vendors" are
implementation choices, not the pitch. The actual claim is the trust
boundary in §1. Also explicitly out of scope per `docs/Suggestions.md`
§9 and this session's own scoping: a real-world, independently-reviewed
labeled corpus (needs human domain-expert judgment, not something to
manufacture); a live device-apply path (deliberately never built — see
`services/remediation/app/decision.py`'s own docstring).

---

## 6. Doc audit — full inventory

44 markdown files exist outside `.venv`/`.pytest_cache`/vendor noise.
Status legend: **C** current, **S** stale/needs refresh, **D** duplicate,
**X** scratch/disposable, **H** historical (keep, relabel).

### 6.1 Root

| File | Status | Recommendation |
|---|---|---|
| `README.md` | C | Keep — primary entry point |
| `BUILD_GUIDE.md` | S | One stale claim (`services/schema/` described as pre-existing when it wasn't at time of writing) — 3-way overlap with CONTRIBUTING.md/TEAM_OWNERSHIP.md, see §6.4 |
| `CONTRIBUTING.md` | C | Keep, but see §6.4 merge note |
| `Changestobemade.md` | X | Session-scratch fix log, all items done — prune or fold into a changelog if one gets built |
| `ENV_VARS.md` | C | Keep |
| `TEAM_OWNERSHIP.md` | X | Blank name fields, abandoned team-assignment scratch — prune or repurpose as a lane-map without names |
| `context.md` | C, but see §6.4 | Most load-bearing single doc, but overlaps 3-way with ARCHITECTURE_ADVANCED_FEATURES.md/HANDOVER_REPORT_2026-09-09.md |

### 6.2 `docs/`

| File | Status | Recommendation |
|---|---|---|
| `ARCHITECTURE_ADVANCED_FEATURES.md` | C, overlap | ~80% overlap with `context.md` §5 — see §6.4 |
| `Additional-Features.md` | C | Keep — proposal/spec doc, lineage from Suggestions.md |
| `ArchitecturalChanges.md` | C | Keep — most current status-tracked decision log, several items still 🔴 |
| `HANDOVER_REPORT_2026-09-09.md` | C, overlap | Keep as historical session record, but see §6.4 |
| `LOCAL_LLM_SETUP.md` | C | Keep |
| `MEMORY.md` | C, overlap | Keep as engineering-conventions doc; 30-40% content overlap with HANDOVER_REPORT_2026-09-09.md §3's bug log |
| `PRESENTATION_CLAIMS_CHECKLIST.md` | S | **Needs a refresh pass** — vendor/benchmark claims are behind §3.1 above |
| `RELEASE_CHECKLIST.md` | C | Keep |
| `REMEDIATION_REPORTING_DEMO.md` | C | Keep |
| `SIH26155_NetAudit_Architecture_Blueprint.md` | H | Keep, relabel clearly as "original target spec, superseded by current-state docs" — `docs/report.md` documents it doesn't even compile as written |
| `Suggestions.md` | H | Keep as ideation history — absorbed into Additional-Features.md/ArchitecturalChanges.md/this report |
| `THREAT_MODEL.md` | C | Keep |
| `action.md` | C | Keep — most current capability record alongside this report |
| `report.md` | H | Keep, relabel as historical (already self-aware — `context.md` calls it out as such) |
| `HANDOVER_REPORT_2026-09-25.md` | — | This document |

### 6.3 Duplicates — resolved this session

| Pair | Verdict | Action taken |
|---|---|---|
| `gateway/Architecture.md` == `gateway/app/Architecture.md` | Byte-identical, both current | **Deleted** `app/` copy |
| `gateway/Bludeprint.md` == `gateway/app/Bludeprint.md` | Byte-identical, **both stale** — MIME check + credential redaction were marked `[ ]` but are actually implemented in `uploader.py` | **Fixed** root's checkboxes (both now `[x]`, cited against `uploader.py`), **deleted** `app/` copy |
| `services/ingestion/Architecture.md` ~= `services/ingestion/app/Architecture.md` | Functionally identical (line-ending diff only) | **Deleted** `app/` copy, kept root |
| `services/ingestion/BluePrint.md` vs `services/ingestion/app/BluePrint.md` | **Diverged major** — root had the updated checklist (MIME + redaction checked, correctly), `app/` was the stale all-unchecked fork. But root **overclaimed**: it checked off dedup enforcement, and `uploader.py` never actually calls `stat_object`/checks for an existing hash before writing | **Fixed** root's dedup checkbox back to `[ ]` with an accurate note, **deleted** `app/` copy |

Net finding, still worth recording: doc-authority wasn't consistently
root-level or app/-level across these pairs before this fix — it was
inconsistent per-pair, which was its own hygiene problem independent of
the individual staleness. Root-level is now the sole copy for all four,
matching where `README.md` already lives.

### 6.4 Consolidation candidates

- **Onboarding 3-way**: `BUILD_GUIDE.md` + `CONTRIBUTING.md` + `TEAM_OWNERSHIP.md` → one onboarding doc. `TEAM_OWNERSHIP.md`'s blank fields suggest the lane-split model itself may be moot post-hackathon-team-phase — worth asking whether it's still needed at all before merging it in.
- **"2026-09-09 session" 4-way**: `context.md` + `ARCHITECTURE_ADVANCED_FEATURES.md` + `HANDOVER_REPORT_2026-09-09.md` + `MEMORY.md` → the same six features narrated four times (changelog / design-rationale / handover-report / lessons-learned framing). A single doc with those as sections would cut real duplication without losing any angle.
- **Claims-discipline paragraph**: near-identical "don't overclaim" boilerplate repeated verbatim across `presentation/FINAL_PROTOTYPE_DECK.md`, `presentation/PANELIST_GUIDE.md`, and `demo/DEMO_SCRIPT.md`'s footer — candidate to consolidate into one canonical source the other three link to.

### 6.5 Doc-vs-code drift found this session (fix independent of any restructuring)

- `benchmarks/adversarial/README.md` says `policy_result_deviation`/
  `unsafe_action_escape_rate` return `null` — no longer true as of this
  session's commit `d6aea35`.
- `services/ingestion/BluePrint.md` (root copy) checks off dedup
  enforcement — not actually implemented.
- `docs/report.md` §4.4 item 1 (nginx blocker) — resolved this session.
- `docs/PRESENTATION_CLAIMS_CHECKLIST.md` — vendor/benchmark numbers behind
  §3.1 above.

### 6.6 Genuinely load-bearing, no action needed

`README.md`, `ENV_VARS.md`, `THREAT_MODEL.md`, `LOCAL_LLM_SETUP.md`,
`ArchitecturalChanges.md`, `action.md`, `RELEASE_CHECKLIST.md`,
`REMEDIATION_REPORTING_DEMO.md`, `contracts/README.md`,
`contracts/api_gateway_routes.md`, every `services/*/README.md`,
`frontend/README.md`, `benchmarks/README.md`,
`benchmarks/adversarial/README.md` (pending the one fix above),
`presentation/FINAL_PROTOTYPE_DECK.md`, `presentation/PANELIST_GUIDE.md`,
`demo/DEMO_SCRIPT.md`.

### 6.7 Non-issues

`frontend/AGENTS.md` (machine-regenerated by `next dev`, not hand-authored
— don't manage it as a doc), `frontend/CLAUDE.md` (1-line include pointer),
`graphify-out/GRAPH_REPORT.md` (generated dev-tool snapshot, not a repo
doc — it's already gitignored-equivalent in spirit; it independently
flagged the same Architecture.md staleness found in §6.3, which is a good
sign the tool is useful, not a reason to hand-maintain its output).

---

## 7. Recommended final markdown file set

Proposed target state, **not yet executed** — every deletion/merge below
needs its own confirmation:

```
README.md
CONTRIBUTING.md                 (absorbs BUILD_GUIDE.md's run instructions)
ENV_VARS.md

docs/
  ARCHITECTURE.md                (new — merges context.md +
                                   ARCHITECTURE_ADVANCED_FEATURES.md +
                                   HANDOVER_REPORT_2026-09-09.md +
                                   MEMORY.md into one current-state doc)
  THREAT_MODEL.md
  LOCAL_LLM_SETUP.md
  RELEASE_CHECKLIST.md
  REMEDIATION_REPORTING_DEMO.md
  PRESENTATION_CLAIMS_CHECKLIST.md   (refreshed per §3.1)
  ArchitecturalChanges.md
  action.md
  Suggestions.md                 (relabeled: ideation history)
  Additional-Features.md         (relabeled: spec, lineage from Suggestions.md)
  SIH26155_NetAudit_Architecture_Blueprint.md   (relabeled: original spec)
  report.md                      (relabeled: historical)
  HANDOVER_REPORT_2026-09-09.md  (kept: historical)
  HANDOVER_REPORT_2026-09-25.md  (this report)

contracts/README.md
contracts/api_gateway_routes.md

services/{ingestion,parsing,compliance,remediation,reporting,learning,schema}/README.md
gateway/README.md
gateway/Architecture.md          (single copy, app/ duplicate deleted)
frontend/README.md

benchmarks/README.md
benchmarks/adversarial/README.md (fixed per §6.5)

demo/DEMO_SCRIPT.md
presentation/FINAL_PROTOTYPE_DECK.md
presentation/PANELIST_GUIDE.md
```

Dropped from the current set: `Changestobemade.md`, `TEAM_OWNERSHIP.md`
(pending the question in §6.4), all four `app/`-level `Architecture.md`/
`Bludeprint.md`/`BluePrint.md` duplicates, `frontend/AGENTS.md`/
`frontend/CLAUDE.md` (left as-is, just not treated as doc-set members).

---

## 8. Infra changes made this session

- Added `infra/nginx/{nginx.conf,generate-cert.sh,Dockerfile}` + a new
  `nginx` service in `docker-compose.yml` — resolves `docs/report.md`
  §4.4's "demo-day blocker."
- Removed `infra/minio/` and `infra/ollama/` (placeholder-only folders,
  confirmed nothing needs them — bucket creation is app-side in ingestion,
  and no compose logic consumes a committed ollama artifact).
- Committed separately: `d6aea35` (agent firewall `actor_type` check,
  topology-aware blast radius, provenance `rule_id`, adversarial benchmark
  metrics fill-in) and `db57f4b` (minio/ollama folder removal).
