# NetAuditor — Codebase Context

A working reference for the architecture, the design rules that hold it together, and
the changes made in the session dated 2026-09-09. See also
`docs/ARCHITECTURE_ADVANCED_FEATURES.md` (full design writeup of the six features
below), `docs/HANDOVER_REPORT_2026-09-09.md` (handover-style report), and
`docs/MEMORY.md` (transferable lessons for future contributors).

---

## 1. What the system does

NetAuditor ingests network device configuration files, normalizes them into a
vendor-neutral schema, evaluates them against compliance frameworks (CIS/NIST/STIG)
with a deterministic policy engine, and produces findings, remediation proposals, and
PDF reports.

The pipeline is a chain of independent services connected by Celery tasks over Redis
and by shared Postgres tables — no service calls another synchronously except through
the Gateway.

```
upload → Ingestion → Parsing → Compliance → Remediation → Reporting
                        ↕                ↕            ↕
                    Learning ─────── Neo4j       Learning
                (RAG, vendor fp,   (topology)   (manuals, anomaly
                 manuals, anomaly)               vectors)
```

---

## 2. Services

| Service | Role | Key entry points |
|---|---|---|
| `gateway` | FastAPI edge: JWT auth, proxies to internal services. Only service with a published port. | `app/main.py`, `app/auth.py` |
| `ingestion` | Accepts uploads, validates, redacts, chunks, stores to MinIO, creates the `audit_runs` row, queues `parsing.process_config`. | `app/main.py`, `app/uploader.py` |
| `parsing` | Celery worker. Detects vendor, calls the SLM (Ollama) per chunk with RAG context, normalizes, gates on confidence/logprob/reverse-translation fidelity, merges chunk baselines, emits `compliance.evaluate_baseline`. | `app/worker.py`, `app/slm_client.py` |
| `compliance` | Celery consumer. Evaluates the baseline against the OPA Rego bundle, scores risk, persists findings, enriches with GraphRAG blast radius and (separately) an anomaly-detection signal. **Contains no LLM calls.** | `app/evaluator.py`, `app/opa_client.py` |
| `learning` | Owns all vector-DB (ChromaDB) concerns: RAG mappings, vendor fingerprints, remediation manuals, baseline vectors for anomaly detection, and the human review queue for unparseable chunks. | `backend/app/main.py` |
| `remediation` | Renders version-controlled Jinja2 CLI fixes, runs Batfish/static preflight, records human approval. Has an agentic-RAG fallback for vendors with no template. | `app/main.py`, `app/template_engine.py` |
| `reporting` | Generates the audit PDF (WeasyPrint), now surfaces `source`/`rollback_script`/`blast_radius`. | `app/pdf_service.py` |
| `schema` | Shared Python package defining `SecurityBaseline` (Pydantic v2), including `topology`. Installed by Parsing; the single source of truth for the normalized shape. | `schema/security_baseline.py` |

**Infrastructure** (`docker-compose.yml`): postgres, redis (Celery broker), minio, chromadb,
opa, ollama, batfish, neo4j, frontend. The `audit-net` network is `internal: true`; only
the gateway publishes a port. `neo4j` takes `environment: [NEO4J_AUTH=...]`, not
`env_file` — see §7.

---

## 3. Design rules that hold across the codebase

These are the non-obvious invariants. Violating them tends to break something silently.

**Vendor-agnostic by construction.** There is deliberately *no* per-vendor Rego bundle.
One `policies/generic/generic_level1.rego` evaluates every device identically, regardless
of `input.device.detected_vendor`, because a per-vendor model can only ever cover "the
vendors someone remembered to add." Vendor-specific remediation template selection lives
as *data* inside that bundle, not as code. Never add per-vendor detection, gating, or
compliance branching.

**Confidence gates, vendor recognition does not.** An unrecognized vendor is not the same
thing as an unparseable device. Whether a baseline reaches Compliance depends solely on
extraction quality (`parsing_confidence`, the logprob gate, and the reverse-translation
fidelity gate), never on whether the regex fingerprinter knew the vendor's name. Flooring
confidence against vendor-detection confidence would silently re-create a vendor
allowlist through the math.

**Optional enrichment degrades, never fails.** Learning/RAG, vendor fingerprinting, the
Neo4j topology graph, and the anomaly-detection client are all injectable providers with
a no-op `Empty*` default. An outage in any of them produces less context — never a failed
run. The pattern is a `Protocol` + a real implementation + an `Empty*` fallback selected
by config, built **lazily and memoized** (never at module import — a bad config value
must degrade, not crash the process at startup).

**Safety-critical absences fail closed.** The inverse of the rule above, for anything that
could mislabel a broken device as fine: OPA unreachable *raises* rather than returning
"no findings"; a missing Batfish snapshot returns `UNAVAILABLE`, never `SAFE`; a policy
bundle that isn't loaded is an error, not a clean verdict; an agentic-RAG remediation
proposal can never reach `SAFE` regardless of how well-grounded it is.

**A statistical or generative signal never gets silently promoted to a deterministic
verdict.** Both the anomaly-detection signal and agentic-RAG remediation proposals had a
real conflict with an existing invariant (a stable compliance verdict; no free-form AI
commands) and were resolved by keeping the new thing structurally separate — a different
table, a different response field, a status that can never reach `SAFE` — rather than
blending it into the thing the invariant protects. See §5.3/§5.5 below and
`docs/ARCHITECTURE_ADVANCED_FEATURES.md`'s closing section.

**Contracts are mirrored and drift-tested.** `contracts/*.schema.json` mirror the Pydantic
models by hand. `services/compliance/tests/test_contracts.py` is the one test file that
reaches outside its service: it asserts that `infra/postgres/init.sql` columns, what
`app/db.py` inserts, and the published contract JSON all agree. When adding a persisted
field you must update all three or that test fails.

**Test DB schemas are hand-mirrored.** `tests/test_db.py` in compliance declares its own
SQLite `CREATE TABLE`. It will not pick up an `init.sql` change automatically.

**`init.sql` is not a migration system.** It only runs against a brand-new, empty Postgres
volume. A schema change needs a matching file under `infra/postgres/migrations/`, applied
by hand (`psql "$POSTGRES_DSN" -f ...`) against any database that already exists.

---

## 4. Data contracts

- `contracts/security_baseline.schema.json` — Parsing → Compliance. The OPA `input` document.
  Includes `topology` (`Interface`, `RoutingNeighbor`) since this session.
- `contracts/compliance_finding.schema.json` — Compliance → Remediation/Reporting/Frontend.
  `additionalProperties: false`, so any new field must be declared explicitly. Includes an
  optional `blast_radius` since this session.
- `contracts/ingestion_job.schema.json` — Ingestion → Parsing.
- `contracts/api_gateway_routes.md` — the Gateway's route table.

Celery task names are part of the contract: `parsing.process_config`,
`compliance.evaluate_baseline`, `learning.receive_unknown_block`.

`GET /audit-runs/{id}` (Compliance, proxied by Gateway) now also returns a top-level
`anomaly` object (`{device_id, status, is_anomaly, anomaly_score, peer_count, checked_at}`
or `null`) — not part of a JSON-schema contract file, since it's deliberately not folded
into `findings`.

---

## 5. Changes made this session

### 5.1 Active learning via token uncertainty (logprobs) — **committed**

Flags low-confidence SLM extractions using the model's own token probabilities, rather
than only the field-count heuristic.

- `services/parsing/app/models.py` — `SLMResult(value, mean_logprob)`. `mean_logprob` is
  `None` when the backend reports no logprobs; `None` means *no signal*, never treated as
  low confidence.
- `services/parsing/app/slm_client.py` — requests per-token logprobs from Ollama,
  computes their mean via `_extract_mean_logprob()`. Mock mode derives a plausible value
  from the same fields-found signal as `parsing_confidence`.
- `services/parsing/app/worker.py` — a mean below `LOGPROB_UNCERTAINTY_THRESHOLD`
  (default `-0.5`) routes the chunk to the Learning lane's unknown-block queue.

### 5.2 Multi-agent reverse translation — **uncommitted**

Agent A is the existing forward pipeline. Agent B reconstructs CLI from *only* the JSON
candidate; a fresh forward pass re-extracts JSON from that reconstruction; the two
candidates are diffed for fidelity.

- `services/parsing/app/slm_client.py` — `reverse_translate()` (new), with a mock
  implementation that deterministically inverts the mock forward extractor's own
  patterns, so the round trip is exercisable under `USE_MOCK_SLM=true`.
- `services/parsing/app/reverse_translation.py` *(new)* — `compute_fidelity()`: flattens
  both candidates into order-independent `(path, value)` fact sets and diffs them.
  Excludes device-identity fields (same list as the topology exclusion) and "not
  observed" enum sentinels (`UNKNOWN`, `none`, `NONE`) — neither is a fact Agent A
  actually extracted.
- `services/parsing/app/worker.py` — `_check_reverse_translation_fidelity()` runs Agent B
  + the round-trip re-extraction; a fidelity below `REVERSE_TRANSLATION_FIDELITY_THRESHOLD`
  (default `0.7`) routes the chunk to human review, independently of the logprob gate.
  An SLM failure during this check degrades to "no signal" (skips the gate), not a
  rejection — mirrors the logprob gate's `None`-is-not-negative rule. Roughly triples
  SLM calls per chunk; `ENABLE_REVERSE_TRANSLATION` (default `true`) disables it whole.

### 5.3 GraphRAG topology and blast radius — **uncommitted**

Maps device interfaces and routing adjacency into Neo4j, then answers "which other
devices does this failure put at risk."

- `services/schema/schema/security_baseline.py` — `Interface`, `RoutingNeighbor`,
  `TopologyConfig`; `SecurityBaseline.topology`. Excluded from `parsing_confidence`.
- `services/compliance/app/graph_client.py` *(new)* — `Neo4jTopologyGraphProvider`
  (MERGEs `Device`/`Interface` nodes and `ROUTES_TO` edges), `EmptyTopologyGraphProvider`.
  A routing neighbor is only known by IP until some scanned device turns out to own that
  IP — until then it's parked on an `UnresolvedPeer {ip: ...}` node (a distinct label,
  never `Device`), so `blast_radius` can never return a bare IP where it promises a
  device id. A reconciliation step redirects edges onto the real `Device` node once one
  is ingested for that IP. *(This was a real bug found and fixed by code review — see
  §6.)*
- `services/compliance/app/evaluator.py` — `_get_graph_provider()` builds the driver
  **lazily and memoized**, wrapped in `try/except` (a bad `NEO4J_URI` must not crash the
  service at import time — also a code-review fix, see §6). Ingests every baseline;
  queries blast radius only when findings exist.
- Persistence — `blast_radius JSONB` on `compliance_findings`.

### 5.4 Agentic RAG remediation and rollback — **uncommitted**

Synthesizes CLI + a mandatory rollback for a finding whose vendor has no committed
Jinja2 template. Conflicted with Remediation's documented safety model ("No free-form AI
command generation"); reconciled by scoping the fallback strictly to the gap templates
can't cover, and forcing every agentic-RAG proposal to `RISK_FLAGS` — never `SAFE` —
regardless of grounding or rollback quality, so it can never be approved through the
normal flow the way a reviewed template can.

- `services/learning/backend/app/main.py` — `remediation_manuals` ChromaDB collection.
  Exact `[vendor, os, control_id]` match, not fuzzy embedding search. `os` is stored as
  an explicit `"any"` sentinel, never `None` (ChromaDB rejects `None` metadata — a
  code-review fix, see §6); lookup is a two-tier `$in` match (`[os, "any"]` when known,
  `["any"]` alone when not) so a wrong-OS manual can never answer an unknown-OS query.
- `services/remediation/app/slm_client.py`, `manual_provider.py`, `rag_remediation.py`
  *(new)* — index query → synthesis → rollback, with `grounded` exposed for flagging.
- `services/remediation/app/main.py` — `_build_proposal()` splits template vs. agentic
  paths; agentic-RAG output is unconditionally `RISK_FLAGS`. `USE_MOCK_SLM` defaults to
  `false` here (unlike Parsing's `true` default) since this mock is a fixed placeholder
  string with no relation to the finding — a code-review fix, see §6.
- `services/remediation/app/models.py` — `Finding.remediation: str | None` with **no
  default** (required-but-nullable) — a request that omits the key is a malformed
  caller, not the same as an explicit `null` — a code-review fix, see §6.
- Persistence — `rollback_script`, `source` on `remediation_proposals`.

### 5.5 Unsupervised semantic anomaly detection — **uncommitted**

Flags "configuration drift": a device whose normalized settings sit unusually far from
its vendor+OS peer cohort. Conflicted with Compliance's documented determinism guarantee
("the same normalized baseline always produces the same verdict") since an
`IsolationForest` fit on an evolving peer cohort is not stable over time. Reconciled the
same way as GraphRAG's `blast_radius`: a separate signal, never folded into the verdict.

- `services/learning/backend/app/main.py` — `baseline_vectors` ChromaDB collection
  (`flatten_baseline_for_embedding()` renders a baseline as deterministic,
  order-independent text, excluding device-identity fields). `check_baseline_anomaly()`
  fits `IsolationForest` on the peer cohort *excluding the target*, scores the target as
  a held-out point. Below `ANOMALY_MIN_PEER_COUNT` (default 5) peers, returns
  `insufficient_peers` rather than a fabricated verdict.
- `services/compliance/app/anomaly_client.py` *(new)* — mirrors `graph_client.py`'s
  shape exactly (`Protocol` + `Empty*` + real HTTP client, lazy/memoized construction).
- `services/compliance/app/evaluator.py` — ingests + checks every baseline; the result
  is a separate `anomaly` field on the response, **never** added to `findings`,
  `risk_score`, or `compliance_score`.
- Persistence — new `configuration_anomalies` table (one row per audit run, not per
  control) — a schema-level guarantee of separation from `compliance_findings`, not just
  a convention.

### 5.6 RAG retrieval scalability — **uncommitted**

A follow-up round asked "what does scalable RAG actually need here." The full 6-item
proposal (hierarchical/tree-sitter chunking, cross-encoder reranking, strict metadata
pre-filtering, exact + semantic query caching, domain-adapted embeddings, RAG eval
metrics) was explicitly cut to a bare-minimum, ship-fast scope after investigation showed
two of the six items were genuinely large (see below); the rest are listed as dropped in
§8.

- **ChromaDB client/collection reuse** (`services/learning/backend/app/main.py`) — every
  endpoint used to build a fresh `chromadb.HttpClient()` (which does a tenant/database
  handshake over HTTP on construction) per request. Now one `_get_chroma_client()`
  singleton, reused for the process's life. The embedding model itself was *already*
  cached at the class level inside chromadb's own `SentenceTransformerEmbeddingFunction`
  — confirmed by reading its source before assuming it was the bottleneck.
- **Vendor/OS pre-filtering — a real, live bug, not a hypothetical.** `LearningMapRequest`
  had no vendor/OS field at all, and `search_learning()` did a completely open-ended
  `collection.query()` with no metadata filter — a Juniper mapping could be retrieved as
  few-shot context for a Cisco chunk. Fixed the same way as the remediation-manual index
  (§5.4): `vendor` (default `"unknown"`, never breaking an old caller) + `os` (`"any"`
  sentinel) tags on confirmed mappings, and a `$in` pre-filter in `search_learning()`
  before similarity search runs at all. `rag.py` now sends vendor/os on every retrieval
  call.
- **Exact-hash parse cache** (`services/parsing/app/parse_cache.py`, wired into
  `worker.py`) — SHA-256 of `[vendor, os, normalized chunk text]` in a separate Redis
  logical DB (db 1, distinct from the Celery broker's db 0). A hit skips RAG retrieval
  and the SLM call entirely — real value for fleets with hundreds of devices sharing
  byte-identical NTP/Syslog/AAA blocks. Only a gate-passing parse is ever cached.

**Two real bugs found and fixed during this round, worth remembering (also in
`docs/MEMORY.md`):**
- The first cut of the cache wiring *duplicated* the logprob/reverse-translation gate
  logic instead of replacing it — an `Edit` that inserted new code without removing the
  old block it was meant to replace. Dead code that would `NameError` on an actual cache
  hit (`mean_logprob` referenced but never assigned on that path, since gates are skipped
  entirely on a hit). Caught by running the test suite, not by inspection.
- `redis-py`'s defaults have no connect/socket timeout at all — an unreachable Redis
  **hangs** rather than fails. Turned "cache miss" into "the parsing test suite doesn't
  finish in 120 seconds" the first time it ran. Fixed with explicit
  `socket_connect_timeout`/`socket_timeout` (0.3s/0.5s) plus a belt-and-suspenders
  `asyncio.wait_for` around every call.

**Explicitly out of scope this round** (cut after investigation, not forgotten): BM25
hybrid retrieval and cross-encoder reranking (`rank_bm25`/`flashrank` were installed and
prototyped — the reranker's raw scores turned out to be badly calibrated for this
out-of-domain CLI text, confirmed empirically before the scope-cut decision, see §8), the
0.98-similarity semantic cache tier, hierarchical/indentation-aware chunking, an eval
harness, and contrastive embedding fine-tuning.

---

## 6. Code review — all findings resolved

A full `/code-review` pass (2 High, 5 Medium, 2 Low) was run on §5.3/§5.4 before §5.5 was
built, and every finding was fixed:

- **High:** the `neo4j` compose service would have crash-looped (`env_file: .env` leaked
  app-side `NEO4J_*` vars into the container, which the neo4j image maps into
  `neo4j.conf` and rejects if unrecognized) — fixed with `environment: [NEO4J_AUTH=...]`.
- **High:** GraphRAG blast radius could return bare IPs instead of device ids (neighbor
  placeholders shared the `Device` label/id shape with real devices) — fixed with the
  `UnresolvedPeer` label + reconciliation step (§5.3).
- **Medium × 5:** eager Neo4j driver construction at import time (now lazy/memoized, see
  §5.3); asymmetric OS filtering + `None` ChromaDB metadata in the remediation-manual
  index (now the `"any"` sentinel + two-tier `$in` match, see §5.4); Reporting couldn't
  distinguish AI-synthesized remediation from a reviewed template (now surfaces
  `source`/`rollback_script`/`blast_radius`, corrected the false "no AI" integrity
  claim); no migration path for the new Postgres columns (now
  `infra/postgres/migrations/0001_...sql`).
- **Low × 2:** `USE_MOCK_SLM` defaulting to `true` in Remediation would persist
  placeholder CLI as a real proposal (now defaults `false`); `Finding.remediation`
  becoming optional let a client bug silently trigger agentic-RAG synthesis (now
  required-but-nullable, `is not None` instead of truthiness).

Full detail in `docs/HANDOVER_REPORT_2026-09-09.md` §3.

One unrelated bug was also found (via a `graphify` knowledge-graph pass over the repo,
not the code review) and fixed: `gateway/Architecture.md`, `gateway/app/Architecture.md`,
and `services/ingestion/app/Architecture.md` were stale duplicates of an older
`services/ingestion/Architecture.md`, describing MinIO/Postgres writes as unimplemented
TODOs when they've since been built. All three synced to the current, correct content.

---

## 7. Current state

**Tests:** 275 passing across the five touched services (run independently per service):
schema 8, parsing 75, compliance 101, remediation 55, learning 36. The compliance suite
skips 6 OPA-backed tests when the `opa` binary is not on PATH.

**Not independently verified this session:** Reporting's test suite (`services/reporting/`)
— WeasyPrint needs native GTK/Pango libraries not installed on this Windows dev box. The
template logic itself was verified directly via Jinja2, bypassing the WeasyPrint import.

**Git:** `main` is at `029c0be` (§5.1 committed and pushed there). Everything in §5.2–§5.6
plus the code-review fixes and the Architecture.md sync are uncommitted.

**New docs this session:** `docs/ARCHITECTURE_ADVANCED_FEATURES.md` (design writeup),
`docs/HANDOVER_REPORT_2026-09-09.md` (handover report, Ayush's `docs/report.md` style),
`docs/MEMORY.md` (transferable lessons). `docs/report.md` (Ayush's original handover,
describing the now-superseded Cisco-only bundle) was left untouched — it's a historical
document, not a living one.

---

## 8. Known gaps

- **Bulk remediation endpoint has no agentic-RAG fallback.** `POST
  /remediation/audit-runs/{id}/generate` handles only templated findings —
  `db.get_findings()` doesn't carry device vendor/OS. Needs device-identity columns on
  `audit_runs` and a write path in Compliance to populate them.
- **Ollama logprob support varies by version.** When absent, the uncertainty gate simply
  doesn't fire — intentional (`None` ≠ low confidence), not a bug.
- **The topology graph and the anomaly peer cohort are both single global pools**, with
  no per-tenant/per-network isolation and no decay.
- **Reporting's test suite is unverified in this environment** — needs a run where
  WeasyPrint's native deps are actually installed.
- **Ingestion docs contradiction, unrelated to this session's features, not
  investigated further.** `services/ingestion/`'s own docs (`Architecture.md`,
  `BluePrint.md`) claim MIME checking, credential redaction, and dedup enforcement were
  unimplemented at some point, while a `redact_credentials` symbol currently exists in
  `uploader.py`. Whether the gap is closed or the docs are simply stale wasn't verified.
- **`infra/postgres/init.sql` is invisible to `graphify`.** SQL parsing needs
  `pip install "graphifyy[sql]"`.
- **RAG retrieval quality improvements were scoped out, not forgotten (§5.6).** BM25
  hybrid retrieval + cross-encoder reranking, the 0.98-similarity semantic cache tier,
  hierarchical/indentation-aware chunking for RAG indexing, an eval harness, and
  contrastive embedding fine-tuning were all cut for a bare-minimum, ship-fast pass.
  `rank_bm25` and `flashrank` were prototyped enough to learn that FlashRank's default
  nano cross-encoder (`ms-marco-TinyBERT-L-2-v2`) produces poorly-calibrated absolute
  scores on this out-of-domain CLI text (correct vs. incorrect candidates differed by
  ~10x in raw score, both near zero) — any future reranking work should normalize scores
  within a query's candidate batch rather than threshold on the raw magnitude, or
  evaluate a larger/better-calibrated model first.
- **No migration or GraphRAG/anomaly wiring has been run against a real Postgres/Neo4j
  this session** — only unit-tested against fakes. `docker compose up` plus applying
  both migration files is the remaining verification step before calling any of §5.3–§5.5
  proven end-to-end.
