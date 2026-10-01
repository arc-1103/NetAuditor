-- Digital-twin reachability result for a proposal (services/remediation/app/twin.py):
-- which routing sessions / management paths were checked and whether any would break.
ALTER TABLE remediation_proposals ADD COLUMN IF NOT EXISTS twin JSONB;
