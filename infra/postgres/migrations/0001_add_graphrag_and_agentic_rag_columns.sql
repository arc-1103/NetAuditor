-- Migration: GraphRAG blast radius + agentic RAG remediation columns.
--
-- init.sql only runs once, against an empty data volume
-- (docker-entrypoint-initdb.d fires on first init only) — a `docker compose
-- up` against an EXISTING pgdata volume never re-reads init.sql, so the
-- columns declared there for compliance_findings.blast_radius and
-- remediation_proposals.rollback_script/source never materialize on a
-- database that predates this change. Run this migration by hand against
-- such a database before deploying the code that reads/writes them
-- (services/compliance/app/db.py, services/remediation/app/db.py):
--
--   psql "$POSTGRES_DSN" -f infra/postgres/migrations/0001_add_graphrag_and_agentic_rag_columns.sql
--
-- Idempotent — safe to run against a database that already has these
-- columns (including a brand-new one initialized from the current
-- init.sql), and safe to re-run if it's interrupted partway through.

ALTER TABLE compliance_findings
    ADD COLUMN IF NOT EXISTS blast_radius JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE remediation_proposals
    ADD COLUMN IF NOT EXISTS rollback_script TEXT;

ALTER TABLE remediation_proposals
    ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'template';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'remediation_proposals_source_check'
    ) THEN
        ALTER TABLE remediation_proposals
            ADD CONSTRAINT remediation_proposals_source_check
            CHECK (source IN ('template', 'agentic_rag'));
    END IF;
END $$;
