-- Confidence-weighted decision classification (docs/Additional-Features.md
-- §2) and rollback/undo tracking (§3), both on the proposal they apply to.
--
-- decision_action/decision_rule_id/decision_ruleset_version record which row
-- of services/remediation/policy/decision_table.yaml classified this
-- proposal, and under which version of that table — advisory metadata only,
-- see app/decision.py's docstring for why AUTO_APPLY never bypasses the
-- human-approval gate below.
--
-- pre_change_baseline_sha256 pins the exact audit_evaluations snapshot that
-- was current when this proposal was approved, so a later rollback restores
-- against the config that was actually live at approval time, not whatever
-- audit_runs.baseline_snapshot happens to hold when the rollback runs.
-- applied_at/rollback_status track the rest of §3's lifecycle
-- (Approved -> Applied -> Verified/Rolled back). There is no live
-- device-push anywhere in this codebase (an operator runs `script` by
-- hand), so "applied"/"rolled back" here are operator-attested lifecycle
-- states, not an automated push-and-restore — see app/rollback.py.
ALTER TABLE remediation_proposals
    ADD COLUMN IF NOT EXISTS decision_action TEXT,
    ADD COLUMN IF NOT EXISTS decision_rule_id TEXT,
    ADD COLUMN IF NOT EXISTS decision_ruleset_version TEXT,
    ADD COLUMN IF NOT EXISTS pre_change_baseline_sha256 TEXT,
    ADD COLUMN IF NOT EXISTS applied_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS rollback_status TEXT NOT NULL DEFAULT 'NONE'
        CHECK (rollback_status IN ('NONE', 'APPLIED', 'VERIFICATION_FAILED', 'ROLLED_BACK'));
