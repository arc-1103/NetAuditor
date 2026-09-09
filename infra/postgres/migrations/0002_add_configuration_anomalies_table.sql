-- Migration: unsupervised semantic anomaly detection table.
--
-- Same caveat as 0001_add_graphrag_and_agentic_rag_columns.sql: init.sql
-- only runs once, against an empty data volume. Run this by hand against
-- an existing database before deploying code that reads/writes it
-- (services/compliance/app/db.py's save_anomaly/get_audit_run):
--
--   psql "$POSTGRES_DSN" -f infra/postgres/migrations/0002_add_configuration_anomalies_table.sql
--
-- Idempotent — safe to run against a database that already has this table
-- (including a brand-new one initialized from the current init.sql).

CREATE TABLE IF NOT EXISTS configuration_anomalies (
    audit_run_id   UUID PRIMARY KEY REFERENCES audit_runs(id) ON DELETE CASCADE,
    device_id      TEXT NOT NULL,
    status         TEXT NOT NULL CHECK (status IN ('scored', 'insufficient_peers', 'not_ingested', 'unavailable')),
    is_anomaly     BOOLEAN,
    anomaly_score  DOUBLE PRECISION,
    peer_count     INTEGER,
    checked_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
