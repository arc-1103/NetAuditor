# Blueprint — Ingestion + Gateway

Scoped extract from `docs/SIH26155_NetAudit_Architecture_Blueprint.md`.
This file exists so Claude Code (or any agent working this lane) has the
full technical context in one place without loading the entire 850-line
master blueprint.

## 1. What these two services are, per the master blueprint

**Ingestion Layer** (`services/ingestion/`) — master blueprint §2.1,
`System_Boundary(ingestion)`:
- File Upload API: FastAPI + python-magic. Validates file type, strips
  EXIF/metadata, deduplicates via SHA-256.
- Chunker: splits validated raw config into blocks for downstream parsing.
- Dispatches chunked blocks to the Parsing lane via a queued job.

**API Gateway** (`gateway/`) — master blueprint §2.1,
`System_Boundary(presentation)`, component `api_gateway`:
- FastAPI + JWT Auth.
- All backend services are exposed through this single authenticated
  gateway — nothing else in the system is reachable directly by the
  frontend.

## 2. Canonical sequence (master blueprint §2.2, mermaid sequence diagram)

```
Admin->>GW: POST /api/upload (device.cfg, framework=CIS)
GW->>UPL: Validate file type (python-magic), strip metadata
UPL->>DB: Store raw file → MinIO (SHA-256 fingerprint)
UPL->>DB: Create AuditRun record (status=INGESTED)
UPL->>VF: Dispatch chunked config blocks
```

**Documented deviation in this implementation:** the master blueprint
diagram shows the Gateway itself performing file-type validation before
handing off to Ingestion. This implementation instead has the Gateway
proxy the raw upload untouched, and Ingestion owns all validation
(`services/ingestion/app/uploader.py`). Reasoning: validation logic
(python-magic, size caps, extension allowlist) belongs with the service
that owns the storage write, not duplicated in the routing layer. If a
reviewer holds you to the exact diagram, this is the one place to call
out as an intentional simplification, not an oversight.

## 3. Security requirements that apply to this lane (blueprint §6.2, L1)

```
L1 — Upload Boundary
  • python-magic MIME validation (reject non-text masquerading as .cfg)
  • File size cap: 50MB per upload
  • SHA-256 deduplication (reject already-audited identical cfg)
  • Regex scan for credentials → redact before storage
```

Current implementation status:
- [x] Size cap (`MAX_UPLOAD_SIZE_MB`, default 10MB — **blueprint says 50MB,
      current `.env.example` says 10MB, reconcile this before demo**)
- [x] Extension allowlist (`.cfg,.txt,.conf`)
- [x] SHA-256 hashing for dedup key
- [ ] python-magic MIME check — `uploader.py` currently only checks file
      extension, not actual content type. This is a gap against the
      blueprint's stated defense, not yet closed.
- [ ] Credential redaction regex scan — not yet implemented anywhere.
- [ ] Actual dedup enforcement (currently hashes but doesn't check for
      existing identical upload before proceeding)

## 4. Data contract this lane owns

`contracts/ingestion_job.schema.json` — the payload Ingestion pushes to
Parsing via Celery/Redis. This is NOT in the master blueprint (which only
documents the HTTP-level sequence) — it was written to close a real gap:
the blueprint never specifies the internal queue message shape. Treat
this schema file as authoritative; update it and notify the Parsing lane
before changing `queue_producer.py`'s payload shape.

`contracts/api_gateway_routes.md` — every route the frontend can call,
what it proxies to, and expected response shape.

## 5. Non-goals for this lane

- Parsing logic (vendor detection, SLM inference, schema validation) —
  Parsing lane's job. Ingestion only chunks and dispatches.
- Compliance evaluation, remediation, reporting — downstream, not here.
- Frontend rendering — Gateway only routes and authenticates.