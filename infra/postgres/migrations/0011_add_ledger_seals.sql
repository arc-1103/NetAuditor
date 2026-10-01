-- Tamper-evident sealing of ledger_events (services/compliance/app/ledger_seal.py):
-- each seal commits a Merkle root over a batch of events, is Ed25519-signed, and
-- is chained to the previous seal. Seals are append-only; any edit or delete is
-- refused here and, if bypassed, caught by GET /ledger/verify.
CREATE TABLE IF NOT EXISTS ledger_seals (
    seq            INTEGER PRIMARY KEY,
    merkle_root    TEXT NOT NULL,
    prev_seal_hash TEXT NOT NULL,
    event_count    INTEGER NOT NULL,
    sealed_at      TEXT NOT NULL,
    signature      TEXT NOT NULL,
    key_id         TEXT NOT NULL,
    event_ids      JSONB NOT NULL
);

CREATE OR REPLACE FUNCTION ledger_seals_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'ledger_seals is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS ledger_seals_no_change ON ledger_seals;
CREATE TRIGGER ledger_seals_no_change
    BEFORE UPDATE OR DELETE ON ledger_seals
    FOR EACH ROW EXECUTE FUNCTION ledger_seals_immutable();
