# NetAudit Engine — Architecture

This document traces the system end to end, against the code as it exists
today: every service, the contracts between them, the exact path a
configuration file takes from upload to a signed-off compliance report, and
the reasoning behind the choices that shape it. It is meant to stand alone —
no other document is required to understand this system.

## 1. Design philosophy

Two rules shape every service boundary in this codebase:

1. **AI extracts, it never decides.** An SLM (or a deterministic mock/TextFSM
   path) turns vendor CLI syntax into a normalized schema. Whether a control
   passes or fails is always a deterministic OPA (Rego) policy evaluation —
   never a model output. Low-confidence or invalid extraction routes to
   `NEEDS_REVIEW`; it is never displayed as compliant.
2. **Vendor-agnostic by construction.** There is exactly one policy bundle
   (`services/compliance/policies/generic/generic_level1.rego`) evaluated
   identically for every device, because Parsing normalizes every vendor into
   the same `SecurityBaseline` shape first. Gating on whether a device reaches
   Compliance is confidence-only (extraction quality), never a vendor
   allowlist — an unrecognized vendor is not the same thing as an unparseable
   one.

## 2. Service map

| Service | Role | Entry points |
|---|---|---|
| `frontend/` | Next.js operations console (single-page dashboard) | `src/app/page.tsx`, talks to the gateway via `src/lib/api.ts` |
| `gateway/` | Sole authenticated boundary the frontend can reach; JWT auth, RBAC, proxies every other service | `gateway/app/main.py`, `gateway/app/auth.py` |
| `services/ingestion/` | Validates, redacts, stores and dispatches the raw upload | `app/main.py`, `app/uploader.py`, `app/chunker.py`, `app/queue_producer.py` |
| `services/parsing/` | Vendor/OS detection, SLM (or mock) extraction, schema validation, confidence gating | `app/worker.py` (Celery consumer) |
| `services/schema/` | Shared `SecurityBaseline` Pydantic model, imported by Parsing | `schema/security_baseline.py` |
| `services/compliance/` | OPA evaluation, risk scoring, optional GraphRAG/anomaly enrichment, immutable findings | `app/worker.py`, `app/evaluator.py`, `app/opa_client.py` |
| `services/remediation/` | Deterministic Jinja2 templates (or agentic-RAG fallback), Batfish preflight, human approval gate | `app/main.py`, `app/template_engine.py`, `app/decision.py` |
| `services/reporting/` | HTML preview, PDF, JSON and CEF evidence export | `app/main.py`, `app/pdf_service.py` |
| `services/learning/` | Optional: human-reviewed CLI→field mappings (RAG), vendor fingerprinting, unsupervised anomaly detection | `backend/app/main.py` |
| `contracts/` | Source of truth for every cross-service JSON shape | `ingestion_job.schema.json`, `security_baseline.schema.json`, `compliance_finding.schema.json`, `api_gateway_routes.md` |

Every backend service is a FastAPI app; cross-service work that shouldn't
block an HTTP response (parsing, compliance evaluation) runs as a Celery task
over a shared Redis broker instead of a synchronous call.

## 3. End-to-end flow: upload → report

```text
Browser (frontend)
   │  POST /api/upload (JWT, multipart file)
   ▼
Gateway (gateway/app/main.py)
   │  proxies raw bytes untouched to Ingestion, attaches X-User-Id from the JWT
   ▼
Ingestion (services/ingestion/app/main.py)
   │  validate_and_store(): size cap, extension allowlist, python-magic MIME
   │  check, credential redaction (regex), SHA-256 hash → MinIO object store
   │  create_audit_run(): Postgres row, status=INGESTED
   │  chunk_config(): naive fixed-size line splitter
   │  enqueue_parsing_job() → Celery task `parsing.process_config` (Redis)
   ▼
Parsing (services/parsing/app/worker.py, Celery consumer)
   │  detect_job_context(): regex vendor/OS fingerprint (best-effort only)
   │  per chunk: build_prompt() + RAG context → SLM (Ollama or mock) → JSON
   │    - reject on low mean_logprob (below LOGPROB_UNCERTAINTY_THRESHOLD)
   │    - optional reverse-translation fidelity check (second SLM round-trip)
   │    - normalize_candidate() → SecurityBaseline.model_validate()
   │  merge_baselines() across chunks; TextFSM deterministic cross-check
   │    (agreement.py) feeds `conflicts`, never confidence, independently
   │  parsing_confidence = mean(chunk confidences), derived from extraction
   │  quality alone — never floored by vendor-fingerprint confidence
   │  below CONFIDENCE_THRESHOLD → mark_needs_review(), stop here
   │  else → Celery task `compliance.evaluate_baseline` (Redis)
   │  (any chunk that failed schema validation is also pushed to
   │   `learning.receive_unknown_block` for human review, regardless of
   │   the job's overall outcome)
   ▼
Compliance (services/compliance/app/worker.py → app/evaluator.py)
   │  opa_client.evaluate(): POST the SecurityBaseline to OPA's /v1/data API
   │    against the single vendor-agnostic generic_level1.rego bundle
   │  risk_scorer.score_findings() / summarize(): severity → risk_score,
   │    compliance_score = 100 − Σ(risk_score)
   │  evidence_locator.attach(): ties each finding back to source config lines
   │  optional: graph_client (Neo4j) blast-radius, anomaly_client (ChromaDB
   │    IsolationForest) — both enrichment only, never fold into the verdict
   │  db.save_findings(): persists findings + baseline snapshot immutably;
   │    audit run status → EVALUATED
   │  webhooks.dispatch("VIOLATION_DETECTED") for newly-detected findings only
   ▼
Frontend polls GET /api/audit-runs/{id} until status is EVALUATED/COMPLETE/
NEEDS_REVIEW/FAILED, then renders findings, risk score and blast radius.
   │
   ├─ Remediation (services/remediation/app/main.py), on demand
   │    POST /api/remediation/generate → per finding:
   │      finding.remediation set → render_template() (sandboxed Jinja2,
   │        allow-listed .j2 files only) → Batfish preflight → SAFE|RISK_FLAGS
   │      finding.remediation null  → agentic-RAG fallback
   │        (rag_remediation.py), grounded by Learning's vendor manual
   │        excerpts when available — permanently forced to RISK_FLAGS,
   │        never approvable through the normal gate (see §4)
   │    decision.decide(): confidence-weighted BLOCK / DUAL_APPROVAL /
   │      SINGLE_APPROVAL / AUTO_APPLY tier (policy/decision_table.yaml),
   │      using parser_agreement + blast_radius + severity
   │    POST /api/remediation/{control_id}/approve → RBAC-scoped
   │      (approval_matrix.py); only preflight_status == SAFE can be
   │      approved; apply/rollback are operator-run, logged actions —
   │      there is no live device-push path in this codebase
   │
   └─ Reporting (services/reporting/app/main.py), on demand
        POST /api/reports/generate → requires status EVALUATED/COMPLETE
          → generate_pdf() + record_report(); also serves HTML preview,
            JSON (SIEM/archive) and CEF (SIEM event stream) exports
        GET /api/executive-report, /api/mttr, /api/provenance/{run}/{control}
          → fleet score, trend, MTTR, and a full per-finding provenance
            chain over the same immutable ledger
```

## 4. Safety gates (the parts that must never be bypassed)

- **Parsing confidence gate** (`services/parsing/app/worker.py`): a baseline
  only reaches Compliance if `parsing_confidence >= CONFIDENCE_THRESHOLD`.
  Confidence comes solely from SLM extraction quality (logprob, optional
  reverse-translation fidelity, validation failure ratio) — never from
  whether the regex vendor fingerprinter recognized the vendor.
- **Compliance is deterministic**: `opa_client.evaluate()` raises
  `OPAEvaluationError` rather than returning an empty finding set when OPA is
  unreachable or the policy bundle isn't loaded — a broken policy engine must
  never look like a clean device.
- **Remediation approval gate** (`services/remediation/app/db.approve`): only
  a proposal whose preflight is `SAFE` can be approved. Agentic-RAG-generated
  scripts (used only when no reviewed `.j2` template exists for a vendor) are
  hard-coded to `RISK_FLAGS` and can never pass this gate — see
  `AGENTIC_RAG_MANUAL_VERIFICATION_FLAG` in `services/remediation/app/main.py`.
  Approval only flips a database column; there is no code path anywhere in
  this repo that pushes a command to a live device.
- **Every finding is immutable evidence**: `compliance_finding.schema.json`'s
  `evidence` and `source_lines` fields make every verdict auditable back to
  the exact config text that produced it.

## 5. Deployment topology (`docker-compose.yml`)

Two Docker networks: `audit-net` (internal, no published ports — Postgres,
Redis, MinIO, OPA, the five backend services, and optional
Neo4j/ChromaDB/Batfish/Ollama) and `edge` (only `gateway`, `frontend`, and
`nginx` join this one). Nothing except the gateway, frontend and nginx is
reachable from outside the Compose network.

- **Always on**: `postgres`, `redis`, `minio`, `opa`, `ingestion`, `parsing`,
  `compliance` + `compliance-worker`, `remediation`, `reporting`, `gateway`,
  `frontend`, `nginx`.
- **`--profile advanced`**: `chromadb`, `neo4j`, `batfish`, `learning` +
  `learning-worker` — optional RAG/topology/anomaly enrichment that Compliance
  and Parsing degrade past gracefully when it isn't running (see §7).
- **`--profile model`**: `ollama` + a one-shot `ollama-bootstrap` job that
  pulls the configured model (default `qwen2.5:7b-instruct-q4_K_M`) so an
  air-gapped presentation doesn't need network access after the first pull.
  Without this profile, Parsing and Remediation run in mock-SLM mode.

Celery queues run over the same Redis instance, one named queue per hop
(`parsing`, `compliance`, `learning`) — each worker only consumes its own
queue, so Compliance coming up before Parsing (or vice versa) never drops a
job.

## 6. Frontend

`frontend/` is a single-page Next.js console (`src/app/page.tsx`) that talks
exclusively to the gateway through `src/lib/api.ts`. Every API function
branches on `NEXT_PUBLIC_USE_MOCK_API`: when `true`, it returns fixtures from
`src/lib/mock.ts` instead of calling the gateway — this lets the frontend
lane build and demo against `contracts/api_gateway_routes.md` before a real
backend route exists, and gives `npm run demo` a fully offline walkthrough.

## 7. Design decisions

The "why," not just the "what," for the choices that shape this system —
collected here so they don't have to be re-derived by reading every file
that touches them.

**No decision model in the verdict path, ever.**
Only deterministic OPA/Rego produces a pass/fail. This was tested explicitly
against a proposal to use a closed-weights model ("Jev") for decision-making
and rejected on two independent grounds: it would break the air-gapped/
no-telemetry claim (config leaves the premises to call a hosted API), and
using *any* model — closed or self-hosted — to produce a verdict breaks the
core claim that the model never decides anything. A self-hostable typed
model may only ever sit upstream of the verdict (e.g. vendor-fingerprint
confidence scoring), never in it.
*Enforced in:* `services/compliance/app/opa_client.py` is the only place a
finding is created.

**Compliance gating is confidence-only, never a vendor allowlist.**
Whether a device reaches Compliance depends solely on SLM extraction
quality (`parsing_confidence`), never on whether a regex vendor fingerprint
recognized it. The confidence calculation deliberately does not floor
itself against the fingerprinter's own confidence (which is `0.0` for any
unrecognized vendor) — doing so would silently recreate a vendor allowlist
through the math, after having explicitly removed the equivalent gate. An
unrecognized vendor the SLM nonetheless parses well must not be punished
for a fingerprint miss. This is also why there is exactly one Rego bundle
(`policies/generic/generic_level1.rego`) instead of one per vendor: the
normalized `SecurityBaseline` schema is the only thing the policy reads.
*Enforced in:* `services/parsing/app/worker.py::_process_config`.

**Remediation templates are rendered, never generated by a model, on the
approvable path.**
`render_template()` uses a sandboxed Jinja2 environment
(`jinja2.sandbox.SandboxedEnvironment`) over version-controlled `.j2` files
only — config-derived values are always passed as template *variables*,
never concatenated into template *source*, closing the template-injection
surface entirely. `autoescape` is deliberately `False`: these templates
render plain-text vendor CLI, not HTML, and autoescaping would corrupt
legitimate output (e.g. an `&` in a login banner becoming `&amp;` in the
actual device config).
*Enforced in:* `services/remediation/app/template_engine.py`.

**Agentic-RAG remediation exists, but can never be approved through the
normal gate.**
When no reviewed `.j2` template exists for a vendor/control pair, an SLM may
synthesize CLI grounded in Learning's stored vendor-manual excerpts. This
output is permanently forced to `preflight.status = RISK_FLAGS` — never
`SAFE` — because `db.approve()` only accepts an approval when preflight is
`SAFE`. A synthesized proposal can be read, manually verified against real
vendor documentation, and applied out-of-band, or rejected; it can never
earn the same trust a human-reviewed template has. This was an explicit
design-conflict call: a request for the SLM to synthesize commands and
rollback scripts directly was flagged against the service's own documented
safety model before being scoped this way, rather than implemented as asked.
*Enforced in:* `services/remediation/app/main.py`
(`AGENTIC_RAG_MANUAL_VERIFICATION_FLAG`).

**There is no live-device-apply path, anywhere, today.**
An `AUTO_APPLY` verdict from the decision table is a *classification*, not
an action — nothing in this codebase pushes a command to a real device.
Approval only flips a database column; an operator runs the approved script
by hand, then marks it `APPLIED`. This was a deliberate choice to leave
"eligible for auto-apply once a real apply path exists" unbuilt rather than
half-build a device-push mechanism no safety review has covered yet.
*Enforced in:* `services/remediation/app/decision.py`,
`services/remediation/app/main.py::mark_applied`.

**Credential evidence is captured before redaction, but only ever stored
masked.**
Two claims otherwise contradict each other: "credentials are redacted at
ingest" and "every finding ships its exact source evidence." The fix
captures evidence (pattern type, line number, a SHA-256 of the real value,
and only the last 4 characters) from the *raw* text before redaction, so a
human can still verify a finding — but the actual secret is never persisted
anywhere, in Postgres, MinIO, or a generated report.
*Enforced in:* `services/ingestion/app/uploader.py`
(`capture_credential_evidence`, `_mask_secret`).

**Findings are current-state; a separate ledger is append-only.**
`compliance_findings` stays a replace-on-re-evaluation table (it answers
"what does this run look like now"), rather than being redesigned into an
event log itself. A separate `ledger_events` stream
(`VIOLATION_DETECTED`, `DECISION_MADE`, `APPROVED`, `APPLIED`,
`ROLLED_BACK`, ...) was added instead, because MTTR, rollback, approval
provenance and the webhook dispatcher all need "what happened and when,"
which a mutable current-state table can't answer without this.
*Enforced in:* `infra/postgres/migrations/0006_add_ledger_events.sql`.

**GraphRAG topology and anomaly detection enrich a finding; they never
produce or alter one.**
Blast-radius (Neo4j) and unsupervised anomaly scoring (ChromaDB +
IsolationForest) are attached alongside a finding after OPA has already
decided pass/fail. Both providers degrade to empty/unavailable rather than
raising, and are built lazily so a bad `NEO4J_URI` or `LEARNING_URL` can
never crash the Compliance API at import time — an optional enrichment
failing must not turn an evaluatable baseline into a failed compliance run.
*Enforced in:* `services/compliance/app/evaluator.py`.

## 8. Deliberate simplifications, recorded so they read as decisions, not drift

- **Upload validation lives in Ingestion, not the Gateway.** The Gateway
  proxies the raw upload untouched (`gateway/app/main.py::upload`);
  Ingestion owns all validation (MIME check, size cap, extension allowlist,
  redaction) because it also owns the storage write
  (`services/ingestion/app/uploader.py`). Validation logic belongs with the
  service that owns the write it protects, not duplicated in the routing
  layer in front of it.
- **The queue message shape between Ingestion and Parsing, and the full
  frontend-facing route table, are defined only in `contracts/`** (as JSON
  Schema / a route table respectively) — there is no separate narrative
  description of either elsewhere in this repository. Update those files and
  notify the consuming lane before changing a payload shape.
