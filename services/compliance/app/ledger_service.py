"""Glue between the ledger tables (app/db.py) and the sealing logic (app/ledger_seal.py)."""

import asyncio
import logging
import os

from app import db, ledger_seal

logger = logging.getLogger("netaudit.ledger")
SEAL_INTERVAL_SECONDS = int(os.getenv("LEDGER_SEAL_INTERVAL_SECONDS", "0"))


def _key():
    key = ledger_seal.load_signing_key()
    if key is None:
        raise ledger_seal.LedgerSealError(
            "No ledger signing key is configured (set LEDGER_SIGNING_KEY or LEDGER_SIGNING_KEY_FILE to an Ed25519 private key)"
        )
    return key


async def seal_now() -> dict:
    key = _key()
    events, seals = await db.get_ledger_events(), await db.get_ledger_seals()
    sealed_ids = {i for seal in seals for i in seal["event_ids"]}
    unsealed = [e for e in events if e["id"] not in sealed_ids]
    if not unsealed:
        return {"sealed": 0, "head": _head(seals)}
    seal = ledger_seal.build_seal(unsealed, seals[-1] if seals else None, key)
    await db.insert_ledger_seal(seal)
    return {"sealed": seal["event_count"], "seq": seal["seq"], "merkle_root": seal["merkle_root"],
            "key_id": seal["key_id"], "head": _head(seals + [seal])}


def _head(seals: list[dict]) -> dict | None:
    return {"seq": seals[-1]["seq"], "hash": ledger_seal.seal_hash(seals[-1])} if seals else None


async def verify() -> dict:
    key = _key()
    events, seals = await db.get_ledger_events(), await db.get_ledger_seals()
    by_id = {e["id"]: e for e in events}
    report = ledger_seal.verify_chain(seals, by_id, key.public_key(), set(by_id))
    report["key_id"] = ledger_seal.key_id(key)
    return report


async def proof(event_id: str) -> dict:
    key = _key()
    events, seals = await db.get_ledger_events(), await db.get_ledger_seals()
    by_id = {e["id"]: e for e in events}
    if event_id not in by_id:
        raise KeyError(event_id)
    seal = next((s for s in seals if event_id in s["event_ids"]), None)
    if seal is None:
        raise ledger_seal.LedgerSealError("This event has not been sealed yet")
    return {**ledger_seal.inclusion_proof(seal, by_id, event_id), "public_key": ledger_seal.public_key_pem(key),
            "event": by_id[event_id]}


async def status() -> dict:
    events, seals = await db.get_ledger_events(), await db.get_ledger_seals()
    sealed_ids = {i for seal in seals for i in seal["event_ids"]}
    key = ledger_seal.load_signing_key()
    return {
        "signing_configured": key is not None,
        "key_id": ledger_seal.key_id(key) if key else None,
        "events": len(events),
        "sealed_events": len(sealed_ids & {e["id"] for e in events}),
        "unsealed_events": len([e for e in events if e["id"] not in sealed_ids]),
        "seals": len(seals),
        "head": _head(seals),
        "auto_seal_interval_seconds": SEAL_INTERVAL_SECONDS,
    }


async def seal_forever() -> None:
    """Optional background sealing: LEDGER_SEAL_INTERVAL_SECONDS > 0 and a key configured."""
    while True:
        await asyncio.sleep(SEAL_INTERVAL_SECONDS)
        try:
            result = await seal_now()
            if result["sealed"]:
                logger.info("Sealed %d ledger event(s) as seal %s", result["sealed"], result["seq"])
        except Exception:
            logger.exception("Automatic ledger sealing failed")
