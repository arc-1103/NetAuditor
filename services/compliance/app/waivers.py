"""
Time-bounded waivers ("accepted risk") for failed controls.

A waiver never deletes or hides a finding. The finding stays in the evidence as
a FAIL; reads annotate it WAIVED with who granted it, why, and until when, and
the score is reported both with and without waivers. Waivers live in the
append-only ledger as WAIVER_GRANTED / WAIVER_REVOKED events, so they are
covered by the signed Merkle seals (docs/LEDGER_INTEGRITY.md) and cannot be
quietly edited or removed.

Status is computed from the events and the clock at read time, never stored:
  ACTIVE   granted, not revoked, expiry in the future
  EXPIRED  granted, not revoked, expiry passed — the finding reverts to FAIL
  REVOKED  revoked before expiry

Standard library only: services/reporting keeps an identical copy (checked by
a test), the same pattern as the other small shared modules.
"""

import os
from datetime import datetime, timedelta, timezone

GRANTED = "WAIVER_GRANTED"
REVOKED = "WAIVER_REVOKED"
MAX_DAYS = int(os.getenv("WAIVER_MAX_DAYS", "90"))
MIN_REASON_CHARS = 15


class WaiverError(ValueError):
    pass


def device_key(vendor: str | None, hostname: str | None, config_sha256: str | None = None) -> str:
    """Stable identity for 'the same device' across audits: vendor + hostname,
    falling back to the config hash when the config names no host."""
    if hostname:
        return f"{(vendor or 'unknown').lower()}|{hostname.lower()}"
    return f"sha:{config_sha256 or 'unknown'}"


def parse_time(value) -> datetime:
    if isinstance(value, datetime):
        moment = value
    else:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00").replace(" ", "T", 1))
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def validate_grant(reason: str | None, expires_at, now: datetime, max_days: int = MAX_DAYS) -> datetime:
    """Returns the parsed expiry, or raises WaiverError with a message safe to show."""
    if not reason or len(reason.strip()) < MIN_REASON_CHARS:
        raise WaiverError(f"A waiver needs a written justification of at least {MIN_REASON_CHARS} characters")
    try:
        expiry = parse_time(expires_at)
    except (ValueError, TypeError):
        raise WaiverError("expires_at must be a date/time") from None
    if expiry <= now:
        raise WaiverError("A waiver must expire in the future")
    if expiry > now + timedelta(days=max_days):
        raise WaiverError(f"A waiver may last at most {max_days} days; renew it if the exception is still needed")
    return expiry


def evaluate(events: list[dict], now: datetime) -> list[dict]:
    """All waivers ever granted, newest first, each with a computed status."""
    revoked: dict[str, dict] = {}
    for event in events:
        if event["event_type"] == REVOKED:
            revoked[(event.get("payload") or {}).get("waiver_id")] = event
    waivers = []
    for event in events:
        if event["event_type"] != GRANTED:
            continue
        payload = event.get("payload") or {}
        waiver_id = payload.get("waiver_id") or str(event["id"])
        expiry = parse_time(payload["expires_at"])
        revocation = revoked.get(waiver_id)
        status = "REVOKED" if revocation else "EXPIRED" if expiry <= now else "ACTIVE"
        waivers.append({
            "waiver_id": waiver_id, "audit_run_id": str(event.get("audit_run_id")), "device_key": payload.get("device_key"),
            "control_id": event.get("control_id"), "reason": payload.get("reason"), "ticket": payload.get("ticket"),
            "granted_by": event.get("actor"), "granted_at": str(event.get("created_at")), "expires_at": expiry.isoformat(),
            "status": status,
            "revoked_by": revocation.get("actor") if revocation else None,
            "revoked_reason": (revocation.get("payload") or {}).get("reason") if revocation else None,
        })
    return sorted(waivers, key=lambda w: w["granted_at"], reverse=True)


def active_for_device(waivers: list[dict], key: str) -> dict[str, dict]:
    """{control_id: waiver} for the device's ACTIVE waivers (the latest expiry wins a tie)."""
    chosen: dict[str, dict] = {}
    for waiver in waivers:
        if waiver["status"] == "ACTIVE" and waiver["device_key"] == key:
            current = chosen.get(waiver["control_id"])
            if current is None or waiver["expires_at"] > current["expires_at"]:
                chosen[waiver["control_id"]] = waiver
    return chosen


def annotate(findings: list[dict], waivers: list[dict], key: str) -> list[dict]:
    """Copies of the findings with `waiver` set (ACTIVE) or `waiver_note` (a waiver that has lapsed)."""
    active = active_for_device(waivers, key)
    lapsed = {}
    for waiver in waivers:
        if waiver["device_key"] == key and waiver["status"] in ("EXPIRED", "REVOKED") and waiver["control_id"] not in active:
            lapsed.setdefault(waiver["control_id"], waiver)
    out = []
    for finding in findings:
        item = dict(finding)
        item["waiver"] = active.get(finding.get("control_id"))
        if item["waiver"] is None and finding.get("control_id") in lapsed:
            old = lapsed[finding["control_id"]]
            item["waiver_note"] = f"A waiver {'was revoked' if old['status'] == 'REVOKED' else 'expired'} ({old['expires_at'][:10]}); this finding counts again."
        out.append(item)
    return out


def split(findings: list[dict]) -> tuple[list[dict], list[dict]]:
    """(counting, waived) — assumes findings were run through annotate()."""
    return [f for f in findings if not f.get("waiver")], [f for f in findings if f.get("waiver")]
