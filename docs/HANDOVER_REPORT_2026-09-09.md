# Parsing / Compliance / Remediation / Learning — Feature Handover Report

**Lanes touched:** Parsing (`services/parsing/`), Compliance
(`services/compliance/`), Remediation (`services/remediation/`), Learning
(`services/learning/backend/`) — see `/TEAM_OWNERSHIP.md`
**Session:** 2026-09-09
**Scope of this report:** four features added across the four lanes above,
a full code-review pass with all findings resolved, a follow-up RAG
retrieval-scalability pass, and one unrelated documentation bug found and
fixed along the way.

Section 3 (bugs found) and Section 4 (what other lanes need to know) are
the ones worth reading even if you skip everything else.

---

## 1. What was built

See `docs/ARCHITECTURE_ADVANCED_FEATURES.md` for the full design writeup.
Summary:

| Feature | Lane(s) | Status |
|---|---|---|
| Active learning via token uncertainty (logprobs) | Parsing | Done, committed (`main`, merge `029c0be`) |
| Multi-agent reverse translation | Parsing | Done, uncommitted |
| GraphRAG topology + blast radius | Compliance (+ Neo4j) | Done, uncommitted |
| Unsupervised semantic anomaly detection | Learning + Compliance | Done, uncommitted |
| Agentic RAG remediation fallback | Remediation + Learning | Done, uncommitted |
| RAG retrieval scalability (client reuse, vendor/OS pre-filter, exact-hash cache) | Learning + Parsing | Done, uncommitted — see §1.5 |

The first five went through a full `/code-review` pass. Every finding was
resolved before this report was written — see §3.

### 1.1 New dependencies

- `services/compliance/requirements.txt`: `neo4j==5.24.0`
- `services/learning/backend/requirements.txt`: `scikit-learn` (unversioned,
  matching that file's existing style)

### 1.2 New infrastructure

- `docker-compose.yml`: `neo4j` service (+ `neo4jdata` volume). **Do not**
  give it `env_file: .env` — see §3.1.
- `compliance`/`compliance-worker` now `depends_on` both `neo4j` and
  `learning`.
- `remediation` now `depends_on` `ollama` and `learning`.

### 1.3 New database objects

- `compliance_findings.blast_radius` (JSONB, default `[]`)
- `remediation_proposals.rollback_script` (TEXT, nullable) and `.source`
  (TEXT, `CHECK (source IN ('template','agentic_rag'))`, default `'template'`)
- `configuration_anomalies` (new table, one row per audit run — see §1.4)

Migrations for all three are in `infra/postgres/migrations/`:
`0001_add_graphrag_and_agentic_rag_columns.sql`,
`0002_add_configuration_anomalies_table.sql`. **`init.sql` does not
re-apply these to an existing database** — see §3.2, this bit an earlier
review pass and is now documented in both affected READMEs.

### 1.4 Why `configuration_anomalies` is a separate table, not a column

This was a deliberate design decision, not an oversight. Compliance's own
README states "the same normalized baseline always produces the same
verdict." An `IsolationForest` fit on an evolving peer cohort does not have
that property — the same baseline can flip anomalous/not-anomalous purely
because more peers have since been scanned. Folding the result into
`compliance_findings` (even as a non-scored column) would put a
non-deterministic value inside a table whose whole contract is
determinism. A separate table makes "never affects the verdict" a schema
guarantee instead of a convention someone could violate by accident later.

### 1.5 RAG retrieval scalability — scoped down deliberately

A follow-up ask ("we need scalable RAG") started as a 6-item proposal
(hierarchical chunking, cross-encoder reranking, strict metadata
pre-filtering, exact + semantic caching, domain-adapted embeddings, eval
metrics). After investigation, shipped as a **bare-minimum, fast** cut:

1. **ChromaDB client/collection reuse** — every Learning endpoint built a
   fresh `chromadb.HttpClient()` (a tenant/database HTTP handshake) per
   request. Now a single reused client.
2. **Vendor/OS pre-filtering** — `search_learning()` did a fully
   open-ended `collection.query()` with no metadata filter at all, meaning
   a Juniper mapping could surface as few-shot context for a Cisco chunk.
   This was a real, live bug, not a hypothetical, and is now fixed the
   same way as the remediation-manual index (`vendor`/`os` tags,
   `$in`-filtered query).
3. **Exact-hash parse cache** — SHA-256 of `[vendor, os, chunk text]` in
   Redis skips RAG + the SLM call on a byte-identical repeat.

**Explicitly not built:** BM25 hybrid retrieval + cross-encoder reranking,
a 0.98-similarity semantic cache tier, hierarchical/indentation-aware
chunking, an eval harness, and contrastive fine-tuning. Full reasoning for
each cut in `docs/ARCHITECTURE_ADVANCED_FEATURES.md` §6 — the short version
is that the reranking path was prototyped far enough to discover the
default cross-encoder's scores are badly calibrated for this domain
(worth knowing if anyone picks it back up), and the rest were either
data-blocked (fine-tuning) or judged not worth the risk/complexity for
this pass (semantic caching, hierarchical chunking).

No dedicated tests were written for this round (explicit instruction to
prioritize speed) — verified only by confirming the existing 275-test
suite across all five services still passes unchanged.

---

## 2. Files changed outside each feature's home lane

| File | Change | Why |
|---|---|---|
| `infra/postgres/init.sql` | 3 new columns + 1 new table (see §1.3) | No per-service migration framework exists |
| `infra/postgres/migrations/` | New directory, 2 files | `init.sql` alone doesn't reach existing databases |
| `docker-compose.yml` | `neo4j` service, new `depends_on` edges | Wiring for the two new cross-service calls |
| `contracts/security_baseline.schema.json` | Added `topology` (`Interface`, `RoutingNeighbor`) | Parsing's new output shape, GraphRAG's input |
| `contracts/compliance_finding.schema.json` | Added optional `blast_radius` | Compliance's new output shape |
| `services/compliance/README.md`, `services/remediation/README.md`, `services/learning/README.md` | New sections per feature | Each service's own docs are the primary reference |
| `gateway/Architecture.md`, `gateway/app/Architecture.md`, `services/ingestion/app/Architecture.md` | Synced to match `services/ingestion/Architecture.md` | Unrelated staleness bug found via a knowledge-graph pass — see §3.4 |

---

## 3. Bugs found

### 3.1 The `neo4j` compose service would have crash-looped

`env_file: .env` on the `neo4j` service pulled in `NEO4J_HOST`,
`NEO4J_BOLT_PORT`, `NEO4J_USER`, `NEO4J_PASSWORD` from the root `.env`
alongside `NEO4J_AUTH`. The official `neo4j` image maps every
`NEO4J_`-prefixed variable it receives into `neo4j.conf`
(`NEO4J_HOST` → `host`, `NEO4J_BOLT_PORT` → `bolt.port`, ...) and Neo4j 5
refuses to start on a setting it doesn't recognize. Only `NEO4J_AUTH` is
special-cased by the image. Fixed: the service now declares
`environment: [NEO4J_AUTH=${NEO4J_AUTH}]` instead of `env_file`, so only
the one variable the image actually wants reaches the container. Compose
still auto-loads the root `.env` for that substitution.

### 3.2 GraphRAG blast radius returned bare IPs, not device ids

`graph_client.py`'s original `_write_topology` keyed a routing neighbor's
placeholder node as `Device {id: <its IP>}` — the same label and id shape
as a real, scanned device. Two real devices peering with each other never
got reconciled into one identity, so `blast_radius` could return an IP
string where the contract promises a device id, and multi-hop traversal
dead-ended at any unresolved peer regardless of whether it had since been
scanned. Fixed with a distinct `UnresolvedPeer {ip: ...}` label (never
`Device`) plus a reconciliation step that redirects edges onto the real
`Device` node once one is ingested for that IP — see
`docs/ARCHITECTURE_ADVANCED_FEATURES.md` §3 for the full mechanism.

### 3.3 Neo4j driver construction at module import time

`evaluator.py` originally built the Neo4j driver eagerly at module scope. A
malformed `NEO4J_URI` scheme, or a missing `neo4j` package, would crash
compliance's entire FastAPI app and Celery worker at startup — the exact
failure mode `graph_client.py`'s own optional-enrichment design was
supposed to prevent. Fixed: lazy, memoized construction
(`_get_graph_provider`/`_get_anomaly_provider`) wrapped in `try/except`,
falling back to the `Empty*` provider. Also added the missing shutdown
hook to close the driver at process exit.

### 3.4 Two stale duplicate `Architecture.md` files (found via a knowledge-graph pass, unrelated to this session's features)

`gateway/Architecture.md`, `gateway/app/Architecture.md`, and
`services/ingestion/app/Architecture.md` were byte-identical copies of an
**older** version of `services/ingestion/Architecture.md` — describing
MinIO writes and `AuditRun` persistence as not-yet-implemented TODOs, when
the current `services/ingestion/app/uploader.py` and `db.py` have both
implemented for some time. Anyone reading the wrong copy would believe
ingestion doesn't persist uploads. All three synced to match the current,
correct file. Not related to any of the four features above — surfaced
incidentally while building a `graphify` knowledge graph of the repo for
this session's own context-gathering.

### 3.5 Two Learning-side matching bugs, same root cause

Both from the remediation-manual index (`/learning/remediation-manuals*`):

- `add_remediation_manual` stored `os: None` in ChromaDB metadata when the
  caller omitted an OS. ChromaDB rejects `None` metadata values outright,
  and the endpoint's broad `except Exception` reported the resulting
  validation error as `"ChromaDB unavailable"` — a client-input problem
  disguised as an infrastructure outage.
- `search_remediation_manual`'s OS filter was asymmetric: a lookup with a
  known OS only matched that exact OS (missing vendor-wide guidance), and a
  lookup with *no* known OS matched *every* OS's excerpts — the
  close-but-wrong-manual danger the exact-match design was meant to
  prevent in the first place.

Fixed together: `os` is never stored as `None`, always an explicit `"any"`
sentinel; lookups use a two-tier `$in` match (`[os, "any"]` when the OS is
known, `["any"]` alone when it isn't) so a specific-OS manual can never
answer a different or unknown OS's query.

### 3.6 Two bugs found while wiring the parse cache (§1.5)

- **A code edit duplicated gate-checking logic instead of replacing it.**
  Restructuring `_parse_chunk` to add the cache-hit short-circuit left the
  original logprob/reverse-translation gate block in place *after* the new
  code that already handled it inside the cache-miss branch — dead code
  that would raise `NameError` on an actual cache hit, since `mean_logprob`
  is never assigned on that path (gates are skipped entirely — that's the
  point of a cache hit). Caught by running the test suite immediately
  after, not by inspection; removed.
- **`redis-py` has no default connect/socket timeout, so an unreachable
  Redis hangs rather than fails.** First test run against the wired-up
  cache didn't finish inside a 120-second timeout. Fixed with explicit
  `socket_connect_timeout=0.3`/`socket_timeout=0.5` plus a wrapping
  `asyncio.wait_for` on every call — an unreachable cache now degrades to
  a miss in well under a second, matching every other optional-enrichment
  provider in this codebase.

---

## 4. Corrections / things other lanes should know

### 4.1 Reporting lane

The PDF report's "Integrity & Method" section used to claim, verbatim, "AI
does not decide compliance or generate free-form device commands." That
became false the moment the agentic-RAG remediation fallback shipped.
`services/reporting/app/db.py`'s `get_report_data` now also selects
`source`, `rollback_script` (remediations) and `blast_radius` (findings);
`html_templates/audit_report.html` shows an explicit "⚠ AI-synthesized
remediation" notice and the rollback script when `source == 'agentic_rag'`,
a blast-radius device count per finding, and corrected integrity-section
wording that no longer makes the blanket claim.

**Could not run this lane's test suite in this environment** — WeasyPrint
needs native GTK/Pango libraries not installed on this Windows dev box.
Verified the template logic directly via Jinja2 (bypassing the WeasyPrint
import) instead; a real CI/Linux run should still exercise
`tests/test_pdf_service.py` before this ships.

### 4.2 Whole team — two new migrations need to be run by hand

Neither Compliance nor Remediation's schema changes will reach an existing
Postgres volume on their own — `init.sql` only fires against an empty data
directory. Before deploying this session's changes to any environment with
existing data:

```bash
psql "$POSTGRES_DSN" -f infra/postgres/migrations/0001_add_graphrag_and_agentic_rag_columns.sql
psql "$POSTGRES_DSN" -f infra/postgres/migrations/0002_add_configuration_anomalies_table.sql
```

Skipping this means the first `save_findings`/`save_proposal`/`save_anomaly`
call after deploy fails with `UndefinedColumn` (or a missing-table error
for 0002).

### 4.3 Remediation lane — safety-model change, read before touching `app/main.py`

The agentic-RAG fallback only activates when a finding's `remediation` is
explicitly `null` (compliance's real signal for "no template for this
vendor") — never for a request that merely omits the field, which is now a
422, not silent SLM synthesis. `Finding.remediation` is required-but-nullable
(no default) for exactly this reason; do not add a default back without
re-reading `services/remediation/app/models.py`'s comment on why. Every
`source: "agentic_rag"` proposal is unconditionally `RISK_FLAGS` — this is
intentional and load-bearing (see §1 of `ARCHITECTURE_ADVANCED_FEATURES.md`),
not something to "fix" if it looks overly conservative later. `USE_MOCK_SLM`
now defaults to `false` for this service specifically (unlike Parsing's,
which defaults to `true`) — its mock is a fixed placeholder string, not a
regex extraction of real input, so leaving mock mode on by default in the
shipped stack would persist fake CLI as if it were a real proposal.

### 4.4 Frontend/dashboard lane (not yet built against, flagging for whoever does)

`GET /api/audit-runs/{id}` (Compliance, proxied by Gateway) now also
returns:

```json
{
  "anomaly": {
    "device_id": "...", "status": "scored", "is_anomaly": true,
    "anomaly_score": -0.31, "peer_count": 9, "checked_at": "..."
  }
}
```

`anomaly` is `null` when the run predates this feature or the check never
ran. `status` is one of `scored | insufficient_peers | not_ingested |
unavailable` — only `scored` carries `is_anomaly`/`anomaly_score`. This is
explicitly **not** a compliance verdict (§1.4) — render it as a distinct,
clearly-labeled signal, not folded into the pass/fail findings list.

Each finding in that same response may also carry `blast_radius: [device
ids]` (GraphRAG) — empty when Neo4j is unavailable or the device has no
known routing neighbors, not when the finding itself is absent.

### 4.5 Learning lane — `/learning/map` and `/learning/search` now carry vendor/OS

`LearningMapRequest` gained `vendor` (defaults `"unknown"`, so an old
caller that omits it doesn't break) and `os` (defaults to an internal
`"any"` sentinel). Whatever confirms mappings today — the mapping-ui
referenced in `services/learning/README.md`, if it exists yet — should
start sending the real vendor/OS it already knows, since an unconfirmed
mapping defaulting to `"unknown"` won't be found by a vendor-specific
search later. `RAGSearchRequest` (called internally by Parsing) now also
requires vendor/OS to actually filter; a caller that omits them gets the
old fully open-ended behavior, which is the one case still worth avoiding
going forward.

---

## 5. Known gaps

Being explicit so nobody assumes these are done:

- **Bulk remediation generation doesn't get the agentic-RAG fallback.**
  `POST /remediation/audit-runs/{id}/generate` only handles findings that
  already have a template — `db.get_findings()` doesn't carry device
  vendor/OS, so there's nothing to query the manual index or SLM with.
  Fixing this needs device-identity columns on `audit_runs` and a write
  path in Compliance to populate them.
- **The topology graph and the anomaly peer cohort are both single global
  pools**, with no per-tenant/per-network isolation and no decay — a
  device's peer set (and the routing graph) only ever grows.
- **Ollama logprob support varies by version.** When absent, the
  active-learning gate simply doesn't fire — this is intentional (`None` ≠
  "low confidence"), not a bug, but worth knowing the gate is inert on
  older Ollama builds.
- **Reporting's test suite is unverified in this environment** (§4.1) —
  needs a run somewhere WeasyPrint's native deps are actually installed.
- **The ingestion docs contradiction graphify surfaced is unrelated to
  these features and was not investigated further**: `services/ingestion/`'s
  own docs (`Architecture.md`, `BluePrint.md`) claim MIME-type checking,
  credential redaction, and dedup enforcement were unimplemented at some
  point, while a `redact_credentials` symbol currently exists in
  `uploader.py`. Whether that gap is now closed or the docs are simply
  behind current code was not verified this session.
- **BM25 hybrid retrieval, cross-encoder reranking, semantic query
  caching, hierarchical/indentation-aware chunking, a RAG eval harness, and
  contrastive embedding fine-tuning were all scoped out of §1.5's
  bare-minimum pass**, not forgotten. Reasoning per item in
  `docs/ARCHITECTURE_ADVANCED_FEATURES.md` §6.
- **No migration or GraphRAG/anomaly/cache wiring has been run against a
  real Postgres, Neo4j, or Redis this session** — every service was only
  tested with fakes/mocks in place of the real infrastructure. `docker
  compose up` plus applying both migration files (§4.2) is the remaining
  step before calling any of this proven end-to-end.

---

## 6. Running this work

Each affected service's own README has the full standalone run/test
instructions (`services/parsing/README.md`,
`services/compliance/README.md`, `services/remediation/README.md`,
`services/learning/README.md`). Test counts at the time of this report,
each service run independently:

```
schema:       8 passed
parsing:      75 passed
compliance:   101 passed  (skips 6 OPA-backed tests without the opa binary on PATH)
remediation:  55 passed
learning:     36 passed
```

Full stack: `docker compose up` (add `neo4j` explicitly to `depends_on` if
starting `compliance`/`compliance-worker` in isolation without the rest of
the stack already up).
