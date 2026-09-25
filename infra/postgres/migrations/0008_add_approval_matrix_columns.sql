-- Approval Matrix / Reviewer RBAC (docs/Additional-Features.md §7).
--
-- risk/blast_radius_count are the same values app/decision.py's decision
-- table used to classify this proposal (§2) — persisted here, not
-- re-derived, so app/approval_matrix.py's role check (does this operator's
-- role permit approving THIS proposal) always agrees with the
-- classification that was actually shown to the approver.
--
-- There is no new "who has approved so far" column: the 2-person rule for
-- a DUAL_APPROVAL-classified proposal is satisfied by counting this run's
-- own APPROVED ledger_events by distinct actor (see app/db.approve) —
-- ledger_events is already the append-only source of truth for who did
-- what, so a second copy of that history here would just be a second
-- place it could drift from.
ALTER TABLE remediation_proposals
    ADD COLUMN IF NOT EXISTS risk_tier TEXT CHECK (risk_tier IN ('LOW', 'MEDIUM', 'HIGH')),
    ADD COLUMN IF NOT EXISTS blast_radius_count INTEGER NOT NULL DEFAULT 0;
