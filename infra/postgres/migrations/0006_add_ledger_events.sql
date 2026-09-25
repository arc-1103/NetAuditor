-- Append-only remediation/compliance event ledger (docs/Additional-Features.md
-- §3, §5, §7, §8; tracked as open work in docs/ArchitecturalChanges.md §4).
-- One row per lifecycle event; every consumer (MTTR, rollback, approval
-- provenance, SIEM/webhook dispatch) reads this same stream instead of each
-- growing its own history table. No code path may UPDATE or DELETE a row
-- here — corrections are new rows, the same rule compliance_findings itself
-- breaks (it's mutable current-state) but audit_evaluations follows.
CREATE TABLE IF NOT EXISTS ledger_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_run_id    UUID NOT NULL REFERENCES audit_runs(id) ON DELETE CASCADE,
    -- NULL for a run-level event (e.g. REPORT_GENERATED) that isn't about
    -- one control.
    control_id      TEXT,
    event_type      TEXT NOT NULL CHECK (event_type IN (
        'VIOLATION_DETECTED', 'REMEDIATION_PROPOSED', 'DECISION_MADE',
        'APPROVED', 'REJECTED', 'APPLIED', 'VERIFICATION_FAILED',
        'ROLLED_BACK', 'REPORT_GENERATED'
    )),
    -- User id for a human-attributed event, 'system' for an automated one
    -- (a detected violation, an auto-decision). Never NULL: "who/what/why"
    -- is the whole point of a provenance ledger (Additional-Features.md §3).
    actor           TEXT NOT NULL DEFAULT 'system',
    -- Version of whatever ruleset authorized/blocked this event (e.g. the
    -- confidence-weighted decision table, Additional-Features.md §2) so a
    -- ledger row is always citable against the exact policy that produced
    -- it, not just today's. NULL for events the decision table never gates.
    ruleset_version TEXT,
    payload         JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- MTTR and the timeline view both ask "everything for this run, in order".
CREATE INDEX IF NOT EXISTS idx_ledger_events_run
    ON ledger_events (audit_run_id, created_at);

-- MTTR's actual query: first VIOLATION_DETECTED and first approving
-- APPROVED for the same (run, control) pair.
CREATE INDEX IF NOT EXISTS idx_ledger_events_run_control
    ON ledger_events (audit_run_id, control_id, event_type, created_at);
