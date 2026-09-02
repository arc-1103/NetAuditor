# Architecture — Ingestion + Gateway

## Component diagram (this lane only)

```
                    ┌─────────────────────────────────────┐
   Frontend  ──────▶│  Gateway (gateway/)                  │
   (Next.js)  HTTPS │  - /api/login   (issues JWT)         │
   JWT Bearer        │  - /api/upload  (proxy → Ingestion)  │
                    │  - /api/audit-runs/{id} (proxy → Compliance) │
                    │  auth.py: validates + issues JWT      │
                    │  db.py: Postgres — users table only   │
                    └──────────────┬────────────────────────┘
                                   │ proxies raw upload (httpx)
                                   ▼
                    ┌─────────────────────────────────────┐
                    │  Ingestion (services/ingestion/)      │
                    │  - POST /upload                       │
                    │  uploader.py: validate, hash, store    │
                    │  chunker.py: split into blocks         │
                    │  queue_producer.py: enqueue job         │
                    └───┬───────────────────┬────────────────┘
                        │                   │
                        ▼                   ▼
                 ┌────────────┐      ┌──────────────┐
                 │   MinIO    │      │  Redis/Celery │
                 │ raw-configs│      │  job queue     │
                 └────────────┘      └──────┬────────┘
                                             │ contracts/ingestion_job.schema.json
                                             ▼
                                    Parsing lane (out of scope)
```

## Two separate Postgres relationships — do not conflate

1. **Gateway owns `users`** (`infra/postgres/init.sql`). This is the only
   table Gateway reads/writes. Login → bcrypt check → JWT issue.
2. **Ingestion writes `AuditRun` records** (status=INGESTED) per the
   master blueprint sequence, via `app/db.py::create_audit_run`. The
   `audit_runs` table is bootstrapped in the same `infra/postgres/init.sql`
   (Ingestion-owned section) since there's no per-service migration
   framework yet — never let Gateway's `users` migration touch it or
   vice versa.

Both services connect to the same physical Postgres instance but own
disjoint tables. Never let one service's migration touch the other's
table without a heads-up — see `TEAM_OWNERSHIP.md`.

## Request flow, step by step

1. Frontend calls `POST /api/login` with email/password.
2. Gateway (`auth.py::authenticate_user`) checks `users` table, verifies
   bcrypt hash, issues JWT (`issue_token`).
3. Frontend calls `POST /api/upload` with `Authorization: Bearer <jwt>`
   and the file.
4. Gateway (`main.py::upload`) validates the JWT via `get_current_user`,
   then proxies the raw file to Ingestion over internal HTTP (`httpx`),
   unauthenticated at that hop (internal network, not internet-facing) —
   but forwards the JWT subject as an `X-User-Id` header so Ingestion can
   still attribute the upload.
5. Ingestion (`uploader.py::validate_and_store`) checks size, extension,
   and sniffed MIME type, computes SHA-256, rejects the upload if that
   hash already exists in MinIO (dedup), redacts credential-looking lines,
   and writes the redacted content to MinIO via `put_object`.
6. Ingestion (`main.py::upload_config`) generates a `run_id`, writes an
   `audit_runs` row (status=INGESTED, `uploaded_by` from `X-User-Id` when
   present) via `db.py::create_audit_run`, then calls
   `queue_producer.py::enqueue_parsing_job` with that same `run_id` as
   `job_id` — this lets a later `GET /api/audit-runs/{id}` look up the run
   by the id returned from upload. The Celery payload matches
   `contracts/ingestion_job.schema.json` and is sent as task
   `parsing.process_config` to Redis.
7. Gateway returns `{job_id, status: "queued"}` to the frontend.

## Dependency boundaries (what this lane touches vs. doesn't)

| Depends on | How | Owned by |
|---|---|---|
| Postgres `users` table | direct SQL (`gateway/app/db.py`) | Gateway (you) |
| Postgres `AuditRun` table | direct SQL (`services/ingestion/app/db.py`) | Ingestion (you) |
| MinIO | wired via `uploader.py::get_minio_client` | Ingestion (you) |
| Redis/Celery | `queue_producer.py` | Ingestion (you) |
| Parsing lane's queue consumer | contract only, `contracts/ingestion_job.schema.json` | Parsing lane |
| Compliance service | HTTP proxy, `COMPLIANCE_URL` | Compliance lane |
| JWT secret (`JWT_SECRET`) | shared value, root `.env` | Whoever else validates tokens — currently nobody else does |

Nothing downstream (Parsing, Compliance, Remediation, Reporting, Learning)
needs your code to import or call directly. The only coupling points are
the two contract files above — treat them as your public API.