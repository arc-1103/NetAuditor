from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import httpx
import pytest

from app import db, main, waivers as w

RUN = "run-1"
KEY = "cisco|edge-rtr1"
FINDINGS = [
    {"control_id": "CIS-NET-1.1.2", "severity": "CRITICAL", "title": "Telnet", "risk_score": 40, "evidence": "e", "source_lines": []},
    {"control_id": "CIS-NET-1.8.1", "severity": "MEDIUM", "title": "Syslog", "risk_score": 10, "evidence": "e", "source_lines": []},
]


class Ledger:
    def __init__(self):
        self.events = []

    async def get_waiver_events(self):
        return list(self.events)

    async def insert_waiver_event(self, event_id, audit_run_id, control_id, event_type, actor, payload):
        self.events.append({"id": event_id, "audit_run_id": audit_run_id, "control_id": control_id, "event_type": event_type,
                            "actor": actor, "payload": payload, "created_at": datetime.now(timezone.utc).isoformat()})


@pytest.fixture
def ledger(monkeypatch):
    fake = Ledger()
    monkeypatch.setattr(db, "get_waiver_events", fake.get_waiver_events)
    monkeypatch.setattr(db, "insert_waiver_event", fake.insert_waiver_event)
    run = {"id": RUN, "device_key": KEY, "status": "EVALUATED", "file_hash": "h", "findings": [dict(f) for f in FINDINGS]}
    monkeypatch.setattr(db, "get_audit_run", AsyncMock(side_effect=lambda run_id: dict(run, findings=[dict(f) for f in FINDINGS]) if run_id == RUN else None))
    monkeypatch.setattr(main, "_seal_quietly", AsyncMock())
    return fake


async def call(method, path, **kwargs):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url="http://t") as client:
        return await client.request(method, path, **kwargs)


def expiry(days=30):
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


GRANT = {"audit_run_id": RUN, "control_id": "CIS-NET-1.1.2", "reason": "Isolated legacy system for mission 4417", "ticket": "CHG-88"}


@pytest.mark.asyncio
async def test_granting_a_waiver_annotates_the_finding_and_stops_it_counting(ledger):
    before = (await call("GET", f"/audit-runs/{RUN}")).json()
    assert before["summary"]["total_findings"] == 2 and before["summary"]["waived"] == 0

    granted = await call("POST", "/waivers", json={**GRANT, "expires_at": expiry()}, headers={"X-User-Email": "admin@netaudit.local"})
    assert granted.status_code == 200 and granted.json()["status"] == "ACTIVE" and granted.json()["granted_by"] == "admin@netaudit.local"

    after = (await call("GET", f"/audit-runs/{RUN}")).json()
    telnet = next(f for f in after["findings"] if f["control_id"] == "CIS-NET-1.1.2")
    assert telnet["waiver"]["reason"].startswith("Isolated legacy") and len(after["findings"]) == 2   # not hidden
    assert after["summary"]["total_findings"] == 1 and after["summary"]["waived"] == 1
    assert after["summary"]["compliance_score"] > after["summary"]["score_without_waivers"]
    row = next(r for r in after["control_results"] if r["control_id"] == "CIS-NET-1.1.2")
    assert row["result"] == "WAIVED"


@pytest.mark.asyncio
async def test_revoking_returns_the_finding_to_the_score(ledger):
    waiver_id = (await call("POST", "/waivers", json={**GRANT, "expires_at": expiry()})).json()["waiver_id"]
    revoked = await call("POST", f"/waivers/{waiver_id}/revoke", json={"reason": "system patched"}, headers={"X-User-Email": "a2@x"})
    assert revoked.json()["status"] == "REVOKED" and revoked.json()["revoked_by"] == "a2@x"
    again = await call("POST", f"/waivers/{waiver_id}/revoke", json={})
    assert again.status_code == 409
    after = (await call("GET", f"/audit-runs/{RUN}")).json()
    assert after["summary"]["total_findings"] == 2 and after["summary"]["waived"] == 0
    assert "revoked" in next(f for f in after["findings"] if f["control_id"] == "CIS-NET-1.1.2")["waiver_note"]


@pytest.mark.asyncio
async def test_guard_rails_reject_bad_grants(ledger):
    assert (await call("POST", "/waivers", json={**GRANT, "reason": "nope", "expires_at": expiry()})).status_code == 422
    assert (await call("POST", "/waivers", json={**GRANT, "expires_at": expiry(-1)})).status_code == 422
    assert (await call("POST", "/waivers", json={**GRANT, "expires_at": expiry(400)})).status_code == 422
    passing = await call("POST", "/waivers", json={**GRANT, "control_id": "CIS-NET-1.2.2", "expires_at": expiry()})
    assert passing.status_code == 422 and "not failing" in passing.json()["detail"]
    assert (await call("POST", "/waivers", json={**GRANT, "audit_run_id": "nope", "expires_at": expiry()})).status_code == 404
    assert ledger.events == []  # nothing was written


@pytest.mark.asyncio
async def test_waiver_is_ledgered_as_an_event_so_the_seals_cover_it(ledger):
    await call("POST", "/waivers", json={**GRANT, "expires_at": expiry()})
    event = ledger.events[0]
    assert event["event_type"] == w.GRANTED and event["payload"]["device_key"] == KEY and event["payload"]["waiver_id"] == event["id"]
    main._seal_quietly.assert_awaited()


@pytest.mark.asyncio
async def test_listing_filters_by_status(ledger):
    await call("POST", "/waivers", json={**GRANT, "expires_at": expiry()})
    assert len((await call("GET", "/waivers?status=active")).json()["waivers"]) == 1
    assert (await call("GET", "/waivers?status=expired")).json()["waivers"] == []
