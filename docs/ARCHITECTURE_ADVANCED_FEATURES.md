# Architecture — Advanced Parsing/Compliance/Remediation Features

Covers five features added on top of the base pipeline (Ingestion → Parsing →
Compliance → Remediation → Reporting, with Learning as the shared vector/ML
service): active learning via token uncertainty, multi-agent reverse
translation, GraphRAG topology and blast radius, unsupervised semantic
anomaly detection, the agentic RAG remediation fallback, and a retrieval
scalability pass over the RAG path shared by all of them. This is a
companion to each service's own README, not a replacement — it exists to
show how the features fit together and why each was scoped the way it was.

## Where each feature lives

```
Parsing (services/parsing/)
├── Active learning via logprobs      — slm_client.py, worker.py
├── Multi-agent reverse translation   — slm_client.py, reverse_translation.py, worker.py
└── Exact-hash parse cache            — parse_cache.py, worker.py, Redis (db 1)

Compliance (services/compliance/)
├── GraphRAG topology + blast radius  — graph_client.py, evaluator.py, Neo4j
└── Anomaly detection (client side)   — anomaly_client.py, evaluator.py, db.py

Learning (services/learning/backend/)
├── Remediation-manual index          — main.py (ChromaDB "remediation_manuals")
├── Anomaly detection (compute side)  — main.py (ChromaDB "baseline_vectors" + IsolationForest)
└── Vendor/OS-filtered RAG search     — main.py (ChromaDB "network_mappings", single reused client)

Remediation (services/remediation/)
└── Agentic RAG fallback              — slm_client.py, manual_provider.py, rag_remediation.py, main.py
```

## 1. Active learning via token uncertainty

**Problem:** field-count confidence (`parsing_confidence`) can look fine even
when the model itself was unsure about the tokens it generated.

**Design:** `OllamaSLMClient.generate()` requests per-token logprobs
alongside the JSON generation and computes their mean
(`_extract_mean_logprob`). `worker.py`'s `_parse_chunk` routes a chunk below
`LOGPROB_UNCERTAINTY_THRESHOLD` (default `-0.5`) to the same Learning-lane
unknown-block queue a schema-validation failure already uses.

**The one rule that matters:** `mean_logprob: None` (no signal — an older
Ollama version, or mock mode without a real decoder) must never be treated
as low confidence. It's a genuinely different case from "logprob was
reported and it was bad."

## 2. Multi-agent reverse translation

**Problem:** a JSON candidate that passes schema validation and has a
plausible-looking confidence score can still have hallucinated or silently
dropped fields — nothing catches that on its own.

**Design:** Agent A is the existing forward pipeline. Agent B
(`OllamaSLMClient.reverse_translate`) takes *only* the normalized JSON — no
access to the original chunk text — and reconstructs plausible CLI. Forward
extraction runs a third time on that reconstruction, and
`reverse_translation.compute_fidelity()` diffs the two JSON candidates as
order-independent (path, value) fact sets. A fidelity below
`REVERSE_TRANSLATION_FIDELITY_THRESHOLD` (default `0.7`) routes the chunk to
human review the same way the logprob gate does — independently: a chunk
can fail one gate and pass the other.

**Cost tradeoff, made explicit:** this roughly triples SLM calls per chunk
(forward, reverse, forward again). `ENABLE_REVERSE_TRANSLATION` (default
`true`) is a single switch to disable it without a code change.

**Exclusions from the diff:** device-identity fields (`detected_vendor`,
`config_sha256`, `parsing_confidence`, …) come from `device_context`/the
file hash, not from what Agent A read out of the text — a mismatch there
says nothing about fidelity. Enum "not observed" sentinels (`UNKNOWN`,
`none`, `NONE`) are excluded the same way: they were never extracted facts,
so losing them on round-trip isn't real data loss.

## 3. GraphRAG topology and blast radius

**Problem:** a compliance finding says "this control failed," but not "which
other devices does that put at risk given how this network actually
routes."

**Design:** Parsing's schema gained a `topology` section (`Interface`,
`RoutingNeighbor`) alongside the existing security fields — deliberately
excluded from `parsing_confidence`, since topology has no bearing on the
CIS/NIST/STIG verdict. `graph_client.py` ingests every evaluated baseline
into Neo4j as `Device`/`Interface` nodes joined by `HAS_INTERFACE`/
`ROUTES_TO` edges, and runs a variable-length Cypher traversal
(`GRAPH_BLAST_RADIUS_MAX_HOPS`, default 3) whenever a baseline has findings.

**The identity problem, and how it's solved:** a routing neighbor is only
known by IP until some scanned device turns out to own that IP on one of
its interfaces. Until then it's parked on an `UnresolvedPeer {ip: ...}` node
— a distinct label, never `Device` — so `blast_radius` can never return a
bare IP where it promises a device id
(`contracts/compliance_finding.schema.json`). A reconciliation step in
`_write_topology` redirects every edge pointing at an `UnresolvedPeer` onto
the real `Device` node as soon as one is ingested for that IP, so multi-hop
traversal keeps working past a peer once it, too, has been scanned. A
neighbor genuinely never scanned stays an `UnresolvedPeer` forever — that's
correct, not a bug: you can't know about a device you've never observed.

**Failure tolerance:** the Neo4j driver is built lazily and memoized
(`_get_graph_provider`), not at module import — a bad `NEO4J_URI` degrades
to `EmptyTopologyGraphProvider` rather than crashing the compliance API and
Celery worker at startup.

## 4. Unsupervised semantic anomaly detection

**Problem:** "configuration drift" — a setting silently changed relative to
every peer device of the same vendor — isn't something a rule-based policy
engine can catch; there's no fixed rule to write for "this looks unusual
compared to its peers."

**Design, split across two services on purpose:**
- **Learning** (`app/main.py`) embeds each baseline (flattened to
  deterministic, order-independent text, with device-identity fields
  excluded the same way reverse-translation excludes them) via the same
  model RAG already uses, and fits an `IsolationForest` on a device's
  vendor+OS peer cohort — excluding the device itself — scoring it as a
  held-out point. Below `ANOMALY_MIN_PEER_COUNT` (default 5) peers, it
  returns `insufficient_peers` rather than a fabricated verdict.
- **Compliance** (`app/anomaly_client.py`, `app/evaluator.py`) calls
  Learning and attaches the result.

**The design tension this reconciles:** Compliance's README says "the same
normalized baseline always produces the same verdict." An `IsolationForest`
fit on an *evolving* peer cohort doesn't have that property — the same
baseline can flip anomalous/not-anomalous purely because more peers have
since been scanned, with nothing about the baseline itself changing. So the
result is **never** folded into `findings`, `risk_score`, or
`compliance_score`. It lands as a separate `anomaly` field on the evaluate
response and in its own `configuration_anomalies` table (one row per audit
run, not per control) — a schema-level guarantee, not just a convention,
that this statistical signal can't quietly become part of the deterministic
verdict later. This is the same reasoning `blast_radius` already follows
(it, too, changes over time as more devices get scanned) — attached as
context on a finding OPA already decided, never part of the decision
itself.

## 5. Agentic RAG remediation fallback

**Problem:** a finding whose vendor has no committed `.j2` template gets
`remediation: null` and nothing else — no proposal at all, not even a draft
to work from.

**Design tension, and how it was resolved:** the remediation service's
safety model is explicit: *"No free-form AI command generation; all
commands are version-controlled Jinja2 templates."* An LLM-synthesized
remediation directly conflicts with that. The fallback exists only for the
gap the template system already can't cover, and it never earns the trust a
reviewed template has:

1. **Remediation Index Query** — `manual_provider.py` asks Learning for
   vendor-manual excerpts indexed by exact `[control_id, vendor, OS]` match
   (not fuzzy embedding similarity — a close-but-wrong manual would be
   dangerous grounding for CLI synthesis). OS matching has two tiers: a
   known-OS lookup matches that exact OS plus vendor-wide `"any"`-tagged
   guidance; an unknown-OS lookup matches only `"any"` — never a
   wrong-OS-specific manual.
2. **Contextual CLI Synthesis** — `slm_client.py` asks an SLM to produce CLI
   from that context (or with none, if nothing was indexed).
3. **Rollback Generation** — the SLM is asked for a mandatory inverse
   rollback script alongside the remediation CLI.

**The hard constraint:** every `source: "agentic_rag"` proposal is
unconditionally forced to `preflight_status: RISK_FLAGS` — never `SAFE` —
regardless of grounding or rollback quality. `db.approve()` only accepts an
approval when `preflight_status == 'SAFE'`, so an agentic-RAG proposal can
be read and rejected but **never approved** through the normal flow. It's a
draft for a human to verify against real vendor docs and apply
out-of-band; the system never vouches for it the way it vouches for a
reviewed template. The reporting PDF surfaces this explicitly (an
"AI-synthesized remediation" notice) and the integrity section no longer
makes the blanket "no AI generates commands" claim it made before this
feature existed.

**Known gap, left deliberately unaddressed:** the bulk
`POST /remediation/audit-runs/{id}/generate` endpoint doesn't use this
fallback — `db.get_findings()` only selects persisted compliance-finding
columns, which don't include device vendor/OS, so there's nothing to query
the manual index or SLM with for that path today. Fixing it needs
device-identity columns on `audit_runs` and a write path in Compliance to
populate them — a separate, sizable change.

## 6. RAG retrieval scalability

A follow-up pass asked what "scalable RAG" actually needs here, starting
from a 6-item proposal (hierarchical/tree-sitter chunking, cross-encoder
reranking, strict metadata pre-filtering, exact + semantic query caching,
domain-adapted embeddings, RAG eval metrics). Two items were built as a
deliberate bare-minimum, ship-fast scope after the other four turned out to
be either genuinely large, blocked on data that doesn't exist, or not
actually where the bottleneck was.

**What the investigation found, before deciding what to build:** the
suspected bottleneck (the embedding model reloading per request) wasn't
real — chromadb's own `SentenceTransformerEmbeddingFunction` caches the
loaded model in a class-level dict, confirmed by reading its source. The
actual bottleneck was mechanical: every Learning endpoint built a fresh
`chromadb.HttpClient()` per request, which performs a tenant/database
handshake over HTTP on construction. Separately, `search_learning()` did a
completely open-ended `collection.query()` with no vendor/OS filter at all
— a live bug, not a hypothetical: a Juniper mapping could be retrieved as
few-shot grounding for a Cisco chunk.

**Built:**
- **Client/collection reuse** — one `_get_chroma_client()` singleton
  instead of one per request.
- **Vendor/OS pre-filtering** — `LearningMapRequest` and `RAGSearchRequest`
  now carry `vendor`/`os`; `search_learning()` filters by
  `[vendor, os-or-"any"]` (same two-tier `$in` pattern as the
  remediation-manual index in §5) before similarity search runs, instead
  of searching every vendor's confirmed mappings at once.
- **Exact-hash parse cache** (`services/parsing/app/parse_cache.py`) — SHA-256
  of `[vendor, os, normalized chunk text]` in Redis (a separate logical DB,
  index 1, from the Celery broker's db 0). A hit skips RAG retrieval and
  the SLM call entirely. Only a gate-passing parse is ever cached — a
  failure might succeed later with better context or an improved model.

**Deliberately not built, and why:**
- **BM25 hybrid retrieval + cross-encoder reranking** — prototyped enough
  (`rank_bm25`, `flashrank`) to find a real problem before committing to
  it: FlashRank's default nano cross-encoder (`ms-marco-TinyBERT-L-2-v2`)
  produces raw scores that are badly calibrated for this out-of-domain CLI
  text — a correct candidate and an obviously-wrong one scored ~0.00013 vs
  ~0.00001 in a toy test, both near zero, no usable absolute threshold.
  Making this work would mean either min-max normalizing scores within a
  batch (workable, but changes the CRAG grading semantics — see §5.4's
  `LearningRAGContextProvider` for the shape that would need to adapt) or
  evaluating a larger, better-calibrated reranker first. Either is real
  work, not a quick add.
- **Semantic query cache (0.98 similarity)** — riskier than the exact-hash
  tier (a miscalibrated threshold returns a *different* block's cached
  result), cut to ship the risk-free exact-hash tier alone.
- **Hierarchical/indentation-aware chunking** for RAG indexing, **an eval
  harness**, and **contrastive embedding fine-tuning** — all real, all
  deferred; fine-tuning specifically needs labeled CLI pairs that don't
  exist in this repo and won't be fabricated.

**Two bugs found and fixed while wiring the cache**, both instructive
beyond this feature (see `docs/MEMORY.md`): a code edit that duplicated
gate-checking logic instead of replacing it (dead code that would
`NameError` on an actual cache hit), and `redis-py`'s lack of any default
connect/socket timeout turning an unreachable Redis into a hang instead of
a fast, safe miss.

## Cross-cutting design principles these features all follow

- **Vendor-agnostic by construction.** No feature branches on
  `detected_vendor`. Cohorts, peer groups, and templates key on vendor as
  *data*, never as code paths.
- **Optional enrichment degrades, never fails — and never hangs, which is a
  different requirement.** Every external dependency added by these
  features (Neo4j, Learning's embedding/anomaly endpoints, Redis for the
  parse cache) follows the `Protocol` + real implementation + `Empty*`
  no-op fallback pattern already established by Parsing's RAG and
  vendor-fingerprint providers — an outage produces less context, never a
  failed evaluation. But a caught exception only helps if the failure
  actually raises one: the parse cache's Redis client needed an *explicit*
  connect/socket timeout added, because the client library's own default
  is no timeout at all, and an unreachable dependency that hangs is worse
  than one that fails, degraded fallback or not.
- **A statistical/generative signal is never silently promoted to a
  deterministic verdict.** Anomaly detection and agentic-RAG remediation
  both had a real design tension with an existing invariant (a stable
  verdict; no free-form AI commands), and both were resolved the same
  way — by keeping the new signal structurally separate (a different field,
  a different table, a status that can never reach `SAFE`) rather than
  quietly blending it into the thing the invariant protects.
