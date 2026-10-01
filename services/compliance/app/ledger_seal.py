"""
Tamper-evident sealing of the append-only ledger.

Sealing hashes the not-yet-sealed ledger events into a Merkle tree
(app/merkle.py), signs the root with Ed25519, and chains each seal to the one
before it. Afterwards:

* changing an event breaks its leaf hash -> the root no longer matches;
* deleting an event (or cascading a delete from audit_runs) -> it is listed in
  the seal but missing from the table;
* rewriting a seal without the key -> its signature fails;
* removing a middle seal -> the next seal's prev_seal_hash no longer matches.

What it cannot prove alone: that nothing was removed from the very END of the
chain, or that the key holder didn't re-sign history. Record the `head` hash
(seq + hash) somewhere outside this database — a printed log, a second system
— and keep the private key in Vault or an HSM. See docs/LEDGER_INTEGRITY.md.

The signing key is an Ed25519 private key in PEM form, from LEDGER_SIGNING_KEY
(the PEM text) or LEDGER_SIGNING_KEY_FILE (a path).
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from app import merkle

GENESIS = "0" * 64


class LedgerSealError(Exception):
    pass


def canonical_event(event: dict) -> bytes:
    """The bytes a leaf commits to. Must be identical at seal and verify time."""
    fields = ("id", "audit_run_id", "control_id", "event_type", "actor", "ruleset_version", "payload", "created_at")
    return json.dumps({f: event.get(f) for f in fields}, sort_keys=True, separators=(",", ":"), default=str).encode()


def header_bytes(seal: dict) -> bytes:
    fields = ("seq", "merkle_root", "prev_seal_hash", "event_count", "sealed_at")
    return json.dumps({f: seal[f] for f in fields}, sort_keys=True, separators=(",", ":")).encode()


def seal_hash(seal: dict) -> str:
    return hashlib.sha256(header_bytes(seal) + bytes.fromhex(seal["signature"])).hexdigest()


def load_signing_key() -> Ed25519PrivateKey | None:
    pem = os.getenv("LEDGER_SIGNING_KEY")
    path = os.getenv("LEDGER_SIGNING_KEY_FILE")
    if not pem and path:
        pem = Path(path).read_text(encoding="utf-8")
    if not pem:
        return None
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise LedgerSealError("LEDGER_SIGNING_KEY must be an Ed25519 private key")
    return key


def public_key_pem(key: Ed25519PrivateKey | Ed25519PublicKey) -> str:
    public = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def key_id(key: Ed25519PrivateKey | Ed25519PublicKey) -> str:
    public = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()[:16]


def build_seal(unsealed: list[dict], previous: dict | None, key: Ed25519PrivateKey, *, now: datetime | None = None) -> dict:
    """`unsealed`: events in (created_at, id) order. Returns the seal row to store."""
    if not unsealed:
        raise LedgerSealError("Nothing to seal")
    leaves = [merkle.leaf_hash(canonical_event(e)) for e in unsealed]
    seal = {
        "seq": (previous["seq"] + 1) if previous else 1,
        "merkle_root": merkle.root(leaves).hex(),
        "prev_seal_hash": seal_hash(previous) if previous else GENESIS,
        "event_count": len(unsealed),
        "sealed_at": (now or datetime.now(timezone.utc)).isoformat(),
    }
    seal["signature"] = key.sign(header_bytes(seal)).hex()
    seal["key_id"] = key_id(key)
    seal["event_ids"] = [str(e["id"]) for e in unsealed]
    return seal


def verify_chain(seals: list[dict], events_by_id: dict[str, dict], public_key: Ed25519PublicKey, all_event_ids: set[str]) -> dict:
    problems: list[dict] = []
    previous_hash = GENESIS
    sealed_ids: set[str] = set()
    for index, seal in enumerate(seals):
        where = {"seal": seal["seq"]}
        if seal["seq"] != index + 1:
            problems.append({**where, "kind": "sequence_gap", "detail": f"expected seal {index + 1}"})
        if seal["prev_seal_hash"] != previous_hash:
            problems.append({**where, "kind": "chain_break", "detail": "previous seal is missing or was altered"})
        try:
            public_key.verify(bytes.fromhex(seal["signature"]), header_bytes(seal))
        except (InvalidSignature, ValueError):
            problems.append({**where, "kind": "bad_signature", "detail": "seal header does not match its signature"})
        leaves, missing = [], []
        for event_id in seal["event_ids"]:
            event = events_by_id.get(event_id)
            if event is None:
                missing.append(event_id)
            else:
                leaves.append(merkle.leaf_hash(canonical_event(event)))
        for event_id in missing:
            problems.append({**where, "kind": "missing_event", "detail": f"event {event_id} was deleted"})
        if not missing and leaves and merkle.root(leaves).hex() != seal["merkle_root"]:
            problems.append({**where, "kind": "modified_event", "detail": "an event's content changed after sealing"})
        if len(seal["event_ids"]) != seal["event_count"]:
            problems.append({**where, "kind": "count_mismatch", "detail": "event list does not match the signed count"})
        sealed_ids.update(seal["event_ids"])
        previous_hash = seal_hash(seal) if seal.get("signature") else previous_hash
    head = {"seq": seals[-1]["seq"], "hash": previous_hash} if seals else None
    return {
        "ok": not problems,
        "seals": len(seals),
        "events_sealed": len(sealed_ids),
        "unsealed_events": len(all_event_ids - sealed_ids),
        "problems": problems,
        "head": head,
    }


def inclusion_proof(seal: dict, events_by_id: dict[str, dict], event_id: str) -> dict:
    if event_id not in seal["event_ids"]:
        raise LedgerSealError("Event is not part of this seal")
    leaves = [merkle.leaf_hash(canonical_event(events_by_id[i])) for i in seal["event_ids"]]
    index = seal["event_ids"].index(event_id)
    return {
        "event_id": event_id,
        "leaf_index": index,
        "leaf_hash": leaves[index].hex(),
        "path": merkle.proof(leaves, index),
        "seal": {k: seal[k] for k in ("seq", "merkle_root", "prev_seal_hash", "event_count", "sealed_at", "signature", "key_id")},
    }
