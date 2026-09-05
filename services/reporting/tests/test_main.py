from unittest.mock import AsyncMock

import httpx
import pytest

from app import main

RUN_ID = "11111111-1111-1111-1111-111111111111"


async def request(method, path, **kwargs):
    transport = httpx.ASGITransport(app=main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.request(method, path, **kwargs)


@pytest.mark.asyncio
async def test_health():
    assert (await request("GET", "/health")).json() == {"status": "ok", "service": "reporting"}


@pytest.mark.asyncio
async def test_generate_unknown_run_is_404(monkeypatch):
    monkeypatch.setattr(main.db, "get_report_data", AsyncMock(return_value=None))
    response = await request("POST", "/reports/generate", json={"audit_run_id": RUN_ID})
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_generate_returns_gateway_urls(monkeypatch, tmp_path):
    monkeypatch.setattr(main.db, "get_report_data", AsyncMock(return_value={"id": RUN_ID, "findings": [], "remediations": []}))
    monkeypatch.setattr(main.db, "record_report", AsyncMock())
    monkeypatch.setattr(main, "generate_pdf", lambda run_id, data: tmp_path / f"netaudit-{run_id}.pdf")
    response = await request("POST",
        "/reports/generate", json={"audit_run_id": RUN_ID}, headers={"X-User-Id": "admin-1"}
    )
    assert response.status_code == 200
    assert response.json()["download_url"].endswith(f"/{RUN_ID}/download")
    main.db.record_report.assert_awaited_once()


@pytest.mark.asyncio
async def test_preview_returns_html(monkeypatch):
    monkeypatch.setattr(main.db, "get_report_data", AsyncMock(return_value={"id": RUN_ID, "findings": [], "remediations": []}))
    response = await request("GET", f"/reports/{RUN_ID}/preview")
    assert response.status_code == 200
    assert "Network Security Compliance Report" in response.text


@pytest.mark.asyncio
async def test_json_and_cef_exports(monkeypatch):
    data = {
        "id": RUN_ID, "file_hash": "a" * 64,
        "findings": [{"control_id": "CIS-1", "title": "Test", "severity": "HIGH", "evidence": "bad=true", "risk_score": 20}],
        "remediations": [],
    }
    monkeypatch.setattr(main.db, "get_report_data", AsyncMock(return_value=data))
    json_response = await request("GET", f"/reports/{RUN_ID}/json")
    cef_response = await request("GET", f"/reports/{RUN_ID}/cef")
    assert json_response.status_code == 200
    assert json_response.json()["summary"]["compliance_score"] == 80
    assert cef_response.status_code == 200
    assert cef_response.text.startswith("CEF:0|")
