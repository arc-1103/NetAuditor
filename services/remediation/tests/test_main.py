from unittest.mock import AsyncMock

import httpx
import pytest

from app import main

RUN_ID = "11111111-1111-1111-1111-111111111111"
FINDING = {
    "control_id": "CIS-IOS-1.1.1", "framework": "CIS", "title": "SSH v2",
    "severity": "HIGH", "evidence": "ssh.version = 1", "remediation": "ios_ssh_v2_fix.j2",
}


async def request(method, path, **kwargs):
    transport = httpx.ASGITransport(app=main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.request(method, path, **kwargs)


@pytest.mark.asyncio
async def test_health_reports_loaded_templates():
    response = await request("GET", "/health")
    assert response.status_code == 200
    assert response.json()["templates"] == 20


@pytest.mark.asyncio
async def test_generate_renders_preflights_and_persists(monkeypatch):
    save = AsyncMock()
    monkeypatch.setattr(main.db, "save_proposal", save)
    response = await request("POST", "/remediation/generate", json={"audit_run_id": RUN_ID, "finding": FINDING})
    assert response.status_code == 200
    assert response.json()["preflight"]["status"] == "SAFE"
    assert "ip ssh version 2" in response.json()["script"]
    save.assert_awaited_once()


@pytest.mark.asyncio
async def test_unknown_template_is_422(monkeypatch):
    finding = {**FINDING, "remediation": "not_present.j2"}
    response = await request("POST", "/remediation/generate", json={"audit_run_id": RUN_ID, "finding": finding})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_approve_requires_run_id():
    response = await request("POST", "/remediation/CIS-IOS-1.1.1/approve", json={"approved": True})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_approve_is_audited(monkeypatch):
    approve = AsyncMock(return_value={"control_id": "CIS-IOS-1.1.1", "approval_status": "APPROVED"})
    monkeypatch.setattr(main.db, "approve", approve)
    response = await request("POST",
        "/remediation/CIS-IOS-1.1.1/approve",
        json={"approved": True, "audit_run_id": RUN_ID, "comment": "CAB-42"},
        headers={"X-User-Id": "admin-1"},
    )
    assert response.status_code == 200
    approve.assert_awaited_once_with("CIS-IOS-1.1.1", RUN_ID, True, "admin-1", "CAB-42")


@pytest.mark.asyncio
async def test_non_safe_approval_returns_conflict(monkeypatch):
    monkeypatch.setattr(main.db, "approve", AsyncMock(return_value=None))
    response = await request("POST",
        "/remediation/CIS-IOS-1.1.1/approve",
        json={"approved": True, "audit_run_id": RUN_ID},
    )
    assert response.status_code == 409


@pytest.mark.asyncio
async def test_bulk_generation_uses_persisted_findings(monkeypatch):
    monkeypatch.setattr(main.db, "get_findings", AsyncMock(return_value=[FINDING]))
    save = AsyncMock()
    monkeypatch.setattr(main.db, "save_proposal", save)
    response = await request("POST", f"/remediation/audit-runs/{RUN_ID}/generate")
    assert response.status_code == 200
    assert response.json()["generated"] == 1
    save.assert_awaited_once()
