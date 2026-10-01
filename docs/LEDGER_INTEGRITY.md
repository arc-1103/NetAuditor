# Tamper-evident ledger

`ledger_events` records findings, proposals, decisions, approvals, applies and
rollbacks. Sealing makes silent changes to that history detectable.

## How it works

1. Events not yet sealed are hashed (SHA-256, domain-separated) into a Merkle tree.
2. The root, event count, time and the **previous seal's hash** form a header that is
   signed with an **Ed25519** key. The seal (with the list of event ids it covers) is
   stored in `ledger_seals`, which the database refuses to UPDATE or DELETE.
3. `GET /api/ledger/verify` recomputes everything from the stored events and reports:

| If someone... | Verification reports |
|---|---|
| edits a sealed event | `modified_event` |
| deletes a sealed event, or cascades a delete from `audit_runs` | `missing_event` |
| rewrites a seal | `bad_signature` |
| removes a seal from the middle | `chain_break` / `sequence_gap` |

4. `GET /api/ledger/proof/<event-id>` returns a Merkle inclusion proof and the signed
   seal. An auditor can check it on their own machine, sharing no code with the
   service: `python tools/verify_ledger_proof.py proof.json trusted_public_key.pem`.

## Setup

- Generate a key: `python tools/airgap_bundle.py keygen <dir>` (Ed25519). Use a
  **different key from the update-bundle signing key**. Keep the private key in Vault
  (`LEDGER_SIGNING_KEY`) or a mounted file (`LEDGER_SIGNING_KEY_FILE`), never in git.
- Apply migration `infra/postgres/migrations/0011_add_ledger_seals.sql` on existing
  databases (new databases get it from `init.sql`).
- Seal on demand (admin: Reports → Seal now) or automatically every N seconds with
  `LEDGER_SEAL_INTERVAL_SECONDS`.

## What this does not prove — say so if asked

- **Events are only protected from when they are sealed.** Anything in the window
  before the next seal can still be altered undetected. Seal often.
- **Truncation at the end of the chain is invisible** to the database alone. Record
  the `head` (seq + hash) from `/api/ledger/status` somewhere outside this
  database — a printed log, a second system — after sealing.
- **Whoever holds the private key can re-sign history.** Protect it (Vault, HSM) and
  separate it from database administration. Publish the public key through a
  channel independent of this system.
- It is a signed hash chain with Merkle inclusion proofs, not a distributed
  blockchain: there is no consensus among multiple parties.
- Config hashes and finding data are covered to the extent they are recorded in
  ledger events; the raw uploaded files are protected by their SHA-256 in the
  audit record, not by the seals.
