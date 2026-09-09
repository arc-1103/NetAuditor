# compliance service — Deterministic Compliance Engine

Owner: Compliance / OPA lane (see `/TEAM_OWNERSHIP.md`)

Blueprint §2.1 `System_Boundary(compliance)`. This is the deterministic half
of the pipeline: the same normalized baseline always produces the same
verdict, and every verdict carries the evidence that produced it. Nothing in
here calls an LLM.

## What's in here

| File | Role |
|---|---|
| `policies/generic/generic_level1.rego` | The rules — vendor-agnostic, evaluated identically for every device. Illustrative subset per blueprint §7 |
| `policies/generic/generic_level1_test.rego` | `opa test` cases — one compliant + one violating baseline per control, plus the vendor-independence tests |
| `app/opa_client.py` | Posts the baseline to OPA, walks the result for `deny` sets |
| `app/risk_scorer.py` | Severity → risk weight, and the per-run summary |
| `app/evaluator.py` | The one pass: evaluate → score → GraphRAG/anomaly enrich → persist |
| `app/worker.py` | Celery consumer for `compliance.evaluate_baseline` (from Parsing) |
| `app/main.py` | HTTP: `GET /audit-runs/{id}` (the Gateway proxies here), `POST /evaluate` |
| `app/db.py` | `compliance_findings` + `configuration_anomalies` tables, `audit_runs.status` |
| `app/graph_client.py` | GraphRAG topology client — ingests each baseline's interfaces/routing neighbors into Neo4j, answers blast-radius queries |
| `app/anomaly_client.py` | Unsupervised anomaly detection client — sends baselines to Learning for embedding + IsolationForest peer-cohort scoring |
| `tests/test_contracts.py` | Drift guards on the seams other lanes depend on — see below |

## The drift tests

`tests/test_contracts.py` is the one file that reaches outside this service. It
checks the seams nothing else in the repo would notice breaking until
integration day:

- Every finding the real Rego bundle emits validates against
  `contracts/compliance_finding.schema.json`, names a `.j2` template, and uses
  a severity `risk_scorer` can weigh.
- `infra/postgres/init.sql`'s columns match what `app/db.py` inserts.
  `tests/test_db.py` declares its own SQLite table, so without this the two can
  drift apart silently.
- `docker-compose.yml` still starts OPA with `run --server` and the bundle
  mounted, still runs a Celery worker, and MinIO still has its data volume.

The OPA-backed half needs the `opa` binary on PATH and skips without it, so
`pytest` is green either way (72 tests with opa, 66 + 6 skipped without).

## Deploying to an existing database

`infra/postgres/init.sql` only runs against a brand-new `pgdata` volume — an
existing database needs both migrations applied by hand first, or the
corresponding `save_*` call fails with `UndefinedColumn` after this deploys:

```bash
psql "$POSTGRES_DSN" -f infra/postgres/migrations/0001_add_graphrag_and_agentic_rag_columns.sql
psql "$POSTGRES_DSN" -f infra/postgres/migrations/0002_add_configuration_anomalies_table.sql
```

0001 adds `blast_radius` to `compliance_findings` (`save_findings`); 0002
adds the whole `configuration_anomalies` table (`save_anomaly`).

## Run standalone

```bash
cp .env.example .env

# 1. The policies — no Docker, no Python, no running services needed.
opa test policies/ -v
opa check --strict policies/

# 2. The Python around them.
pip install -r requirements-dev.txt
pytest

# 3. The service against a live OPA.
opa run --server --addr localhost:8181 policies/ &
OPA_URL=http://localhost:8181/v1/data uvicorn app.main:app --reload --port 8002
```

Then evaluate a config without needing Ingestion, Parsing, or Postgres —
`audit_run_id` is what turns persistence on, so leaving it out is a dry run:

```bash
curl -s localhost:8002/evaluate -H 'Content-Type: application/json' -d '{
  "framework": "CIS",
  "baseline": {
    "device": {"detected_vendor": "cisco", "config_sha256": "'"$(printf a%.0s {1..64})"'", "parsing_confidence": 0.9},
    "ssh": {"enabled": true, "version": "1-2"},
    "telnet": {"enabled": "ENABLED"},
    "snmp": {"enabled": true, "version": "v2c", "community_strings": ["public"]}
  }
}' | python3 -m json.tool
```

In the full stack: `docker compose up opa compliance compliance-worker`.

## The two contracts this lane sits between

**In** — `contracts/security_baseline.schema.json`, from Parsing. Arrives
either as a Celery task or as a `POST /evaluate` body:

```json
{
  "audit_run_id": "<the job_id Ingestion generated>",
  "framework": "CIS",
  "baseline": { "device": {...}, "ssh": {...}, ... }
}
```

Task name is `compliance.evaluate_baseline` on the Redis broker. Celery queues
it, so the Parsing lane never blocks on this service being up.

**Out** — `contracts/compliance_finding.schema.json`, to Remediation,
Reporting and the Frontend. Only failures are emitted; a control absent from
the list passed. `remediation` names the Jinja2 template the Remediation lane
should render.

## GraphRAG topology and blast radius

`app/graph_client.py` ingests every evaluated baseline's `topology` section
(interfaces and routing neighbors — extracted upstream by Parsing, see
`contracts/security_baseline.schema.json`) into Neo4j as `Device` and
`Interface` nodes joined by `HAS_INTERFACE`/`ROUTES_TO` edges. When a
baseline has findings, `app/evaluator.py` also runs a variable-length Cypher
traversal out to `GRAPH_BLAST_RADIUS_MAX_HOPS` routing hops and attaches the
resulting device ids as `blast_radius` on every finding for that device —
"which other devices does a failure here put at risk, given how this network
actually routes."

A routing neighbor is only known by its IP until some scanned device turns
out to own that IP on one of its interfaces — a peer never scanned is
parked on an `UnresolvedPeer` node (a distinct label, never `Device`), so
`blast_radius` can never return a bare IP where it promises a device id.
`_write_topology`'s reconciliation step redirects every edge pointing at an
`UnresolvedPeer` onto the real `Device` node as soon as one is ingested for
that IP and drops the placeholder, so multi-hop traversal keeps working
past a peer once it, too, has been scanned.

This is optional enrichment, not a compliance gate, following the same
pattern as Parsing's RAG and vendor-fingerprint providers:
`build_topology_graph_provider()` returns a no-op `EmptyTopologyGraphProvider`
whenever `NEO4J_URI` is unset, and `evaluate_baseline` catches any exception
from the real provider and falls back to `blast_radius: []`. A Neo4j outage
degrades the topology enrichment; it never fails the compliance verdict
itself.

## Unsupervised semantic anomaly detection

`app/anomaly_client.py` sends every evaluated baseline to Learning
(`POST /learning/baseline-vectors`), which embeds it (the same model
`services/learning/backend/app/embeddings.py` uses for RAG) and stores the
vector tagged by vendor+OS. `evaluate_baseline` then asks
`POST /learning/baseline-vectors/anomaly-check`, which fits an
`IsolationForest` on the device's vendor+OS peer cohort (excluding the
device itself) and scores it as a held-out point — "configuration drift":
does this device's normalized security settings sit unusually far from its
peers, e.g. a spanning-tree setting silently changed relative to every
other switch of the same vendor. Below `ANOMALY_MIN_PEER_COUNT` peers
(Learning-side setting, default 5) it returns `insufficient_peers` rather
than a fabricated verdict.

**This is a statistical signal, never a compliance verdict**, and it is
kept structurally separate from one: this service opens by saying "the same
normalized baseline always produces the same verdict," but an
`IsolationForest` fit on an evolving peer cohort is not stable over time —
the same baseline can flip anomalous/not-anomalous purely because more
peers have since been scanned, with nothing about the baseline itself
changing. So the result lands as a separate `anomaly` field on the evaluate
response and in its own `configuration_anomalies` table (one row per audit
run) — never folded into `findings`, `risk_score`, or `compliance_score`.
This is the same reasoning `blast_radius` already follows: it, too, can
change over time as more devices get scanned, which is why it's attached as
context on a finding OPA already decided, not part of the decision itself.

Optional enrichment, not a compliance gate, same pattern as the topology
graph above: `build_anomaly_detection_provider()` returns a no-op
`EmptyAnomalyDetectionProvider` whenever `LEARNING_URL` is unset, and a
Learning outage degrades to `anomaly: {"status": "unavailable"}` rather
than failing the evaluation.

## Adding a control, or a vendor

A control is one `deny` rule in `generic_level1.rego` plus two cases in its
`_test.rego`. There is deliberately **no per-vendor bundle** — the old
one-bundle-per-vendor model (a `cisco_ios_level1.rego` here, a
`fortinet_level1.rego` there) can only ever cover "the vendors someone
remembered to add," which is exactly what this problem statement rules out.
Every rule reads the same normalized `SecurityBaseline` schema and applies
to every device the same way, regardless of `input.device.detected_vendor`.

Adding **remediation** for a vendor is a data change, not a code change: add
a row to `remediation_templates` in `generic_level1.rego` mapping
`{control_id: {vendor: template_filename}}`. A vendor with no row there still
gets a full compliance verdict — `remediation` just comes back `null`, which
`contracts/compliance_finding.schema.json` already treats as "no template
yet," not an error.

The rule to get right when adding a control is reading optional fields
through `object.get` with an explicit default, and choosing that default
carefully: `input.ssh.version` on a config with no SSH block is *undefined*,
and an undefined expression makes the rule body fail — so the device would
silently pass "SSH must be v2" if you're not careful. But **do not** default
to "insecure" the way a single-vendor bundle safely could — we can no longer
assume any one vendor's out-of-box defaults hold for an arbitrary device.
Fail closed on absence only for the handful of controls where absence is
itself directly observable and universal (a login banner exists; logs go
somewhere off-box) — the header of `generic_level1.rego` explains the split,
and `generic_level1_test.rego::test_verdict_is_identical_regardless_of_vendor_name`
plus `test_empty_config_from_an_unknown_vendor_trips_only_the_universal_controls`
pin it.

## Known gaps

- Only the CIS generic bundle exists. `NIST` and `STIG` are accepted
  framework names but have no policy files, and `opa_client` raises rather
  than returning "compliant" for a framework with no bundle loaded.
- The remediation lookup table only has entries for `cisco` and `fortinet` —
  every other vendor gets a full compliance verdict but `remediation: null`
  until someone adds a `.j2` template and a data row for it.
- `POST /evaluate` is unauthenticated. It sits on the internal network behind
  the Gateway, same as the Ingestion hop.
- The topology graph is a single global graph with no per-tenant/per-network
  isolation. A neighbor device never scanned stays an `UnresolvedPeer` node
  forever — it never gets vendor/os/hostname properties or its own
  findings, and it correctly dead-ends blast-radius traversal there rather
  than being reported as a device.
- Anomaly detection's peer cohort is also global (all devices sharing a
  vendor+OS pair, across every audit run ever evaluated), with no
  per-tenant/per-network isolation and no decay — a device's peer set only
  grows, it never excludes retired or reassigned devices.
