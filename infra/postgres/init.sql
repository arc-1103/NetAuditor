-- Runs automatically on first `docker compose up postgres` via
-- docker-entrypoint-initdb.d (only fires against an empty data volume).
-- Referenced by gateway/app/auth.py and scripts/seed_admin.py.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Owned by Ingestion lane (see services/ingestion/app/db.py). `id` is
-- supplied by the app as the same job_id sent to the Parsing queue, so
-- /api/audit-runs/{id} can look up a run by the id returned from upload.
-- Compliance lane updates `status` (and appends findings elsewhere) as
-- the audit progresses.
CREATE TABLE IF NOT EXISTS audit_runs (
    id                UUID PRIMARY KEY,
    file_hash         TEXT NOT NULL,
    original_filename TEXT,
    storage_path      TEXT NOT NULL,
    uploaded_by       UUID REFERENCES users(id),
    status            TEXT NOT NULL DEFAULT 'INGESTED',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
