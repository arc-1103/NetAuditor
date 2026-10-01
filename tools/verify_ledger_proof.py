"""
Independent check of a NetAudit ledger inclusion proof — needs only the proof
JSON (from GET /api/ledger/proof/<event-id>) and Python's `cryptography`
package. It shares no code with the service, so an auditor can run it on their
own machine.

  python tools/verify_ledger_proof.py proof.json [trusted_public_key.pem]

It recomputes the event's leaf hash, walks the Merkle path to the root, and
checks the Ed25519 signature over the seal header. Pass a public key you
obtained separately to be sure the seal came from the real signer; without it
the key embedded in the proof is used, which only proves internal consistency.
"""

import hashlib
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization


def canonical_event(event: dict) -> bytes:
    fields = ("id", "audit_run_id", "control_id", "event_type", "actor", "ruleset_version", "payload", "created_at")
    return json.dumps({f: event.get(f) for f in fields}, sort_keys=True, separators=(",", ":"), default=str).encode()


def header_bytes(seal: dict) -> bytes:
    fields = ("seq", "merkle_root", "prev_seal_hash", "event_count", "sealed_at")
    return json.dumps({f: seal[f] for f in fields}, sort_keys=True, separators=(",", ":")).encode()


def verify(proof: dict, trusted_key_pem: str | None = None) -> list[str]:
    """Returns the list of failures; empty means the proof holds."""
    failures = []
    leaf = hashlib.sha256(b"\x00" + canonical_event(proof["event"])).digest()
    if leaf.hex() != proof["leaf_hash"]:
        failures.append("event content does not match the proof's leaf hash")
    current = leaf
    for step in proof["path"]:
        sibling = bytes.fromhex(step["hash"])
        pair = sibling + current if step["side"] == "left" else current + sibling
        current = hashlib.sha256(b"\x01" + pair).digest()
    if current.hex() != proof["seal"]["merkle_root"]:
        failures.append("Merkle path does not lead to the sealed root")
    key = serialization.load_pem_public_key((trusted_key_pem or proof["public_key"]).encode())
    try:
        key.verify(bytes.fromhex(proof["seal"]["signature"]), header_bytes(proof["seal"]))
    except InvalidSignature:
        failures.append("seal signature is not valid for this public key")
    return failures


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3):
        print(__doc__)
        return 2
    proof = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    trusted = Path(argv[2]).read_text(encoding="utf-8") if len(argv) == 3 else None
    failures = verify(proof, trusted)
    if failures:
        print("PROOF FAILED:\n - " + "\n - ".join(failures))
        return 1
    source = "the trusted key you supplied" if trusted else "the key embedded in the proof (not independently trusted)"
    print(f"PROOF VALID: event {proof['event']['id']} is part of seal {proof['seal']['seq']}, signed with {source}.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
