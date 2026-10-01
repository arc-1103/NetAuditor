-- Time-bounded waivers are recorded as ledger events (services/compliance/app/waivers.py),
-- so the tamper-evident seals cover them. Extend the allowed event types.
ALTER TABLE ledger_events DROP CONSTRAINT IF EXISTS ledger_events_event_type_check;
ALTER TABLE ledger_events ADD CONSTRAINT ledger_events_event_type_check CHECK (event_type IN (
    'VIOLATION_DETECTED', 'REMEDIATION_PROPOSED', 'DECISION_MADE',
    'APPROVED', 'REJECTED', 'APPLIED', 'VERIFICATION_FAILED',
    'ROLLED_BACK', 'REPORT_GENERATED',
    'WAIVER_GRANTED', 'WAIVER_REVOKED'
));
