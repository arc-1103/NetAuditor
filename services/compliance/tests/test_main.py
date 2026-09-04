"""
Endpoint tests for the compliance HTTP surface. OPA and Postgres are mocked
at the app.main boundary — the policies have `opa test`, and db.py has its own
SQLite-backed tests.
"""

from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from app import main
from app.opa_client import OPAEvaluationError

RUN_ID = "11111111-1111-1111-1111-111111111111"


@pytest.fixture
def client():
    return TestClient(main.app)


def test_health(client):
    resp = client.get("/health")

    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "service": "compliance"}


# ── POST /evaluate ──────────────────────────────────────────────────
def test_evaluate_returns_findings_and_summary(client, monkeypatch, baseline):
    monkeypatch.setattr(
        main,
        "evaluate_baseline",
        AsyncMock(return_value={"findings": [], "summary": {"compliance_score": 100}}),
    )

    resp = client.post("/evaluate", json={"baseline": baseline, "framework": "CIS"})

    assert resp.status_code == 200
    assert resp.json()["summary"]["compliance_score"] == 100


def test_evaluate_passes_audit_run_id_through_for_persistence(client, monkeypatch, baseline):
    spy = AsyncMock(return_value={"findings": [], "summary": {}})
    monkeypatch.setattr(main, "evaluate_baseline", spy)

    client.post("/evaluate", json={"baseline": baseline, "framework": "CIS", "audit_run_id": RUN_ID})

    spy.assert_awaited_once_with(baseline, "CIS", RUN_ID)


def test_evaluate_without_audit_run_id_is_a_dry_run(client, monkeypatch, baseline):
    spy = AsyncMock(return_value={"findings": [], "summary": {}})
    monkeypatch.setattr(main, "evaluate_baseline", spy)

    client.post("/evaluate", json={"baseline": baseline})

    spy.assert_awaited_once_with(baseline, None, None)


def test_evaluate_rejects_unknown_framework_with_400(client, monkeypatch, baseline):
    monkeypatch.setattr(main, "evaluate_baseline", AsyncMock(side_effect=ValueError("Unknown framework 'HIPAA'")))

    resp = client.post("/evaluate", json={"baseline": baseline, "framework": "HIPAA"})

    assert resp.status_code == 400
    assert "HIPAA" in resp.json()["detail"]


def test_evaluate_surfaces_opa_outage_as_502_not_a_clean_verdict(client, monkeypatch, baseline):
    """A dead policy engine must never look like a compliant device."""
    monkeypatch.setattr(main, "evaluate_baseline", AsyncMock(side_effect=OPAEvaluationError("connection refused")))

    resp = client.post("/evaluate", json={"baseline": baseline})

    assert resp.status_code == 502


def test_evaluate_requires_a_baseline(client):
    resp = client.post("/evaluate", json={"framework": "CIS"})

    assert resp.status_code == 422


# ── GET /audit-runs/{id} ────────────────────────────────────────────
def test_get_audit_run_returns_run_findings_and_summary(client, monkeypatch):
    monkeypatch.setattr(
        main.db,
        "get_audit_run",
        AsyncMock(
            return_value={
                "id": RUN_ID,
                "status": "EVALUATED",
                "findings": [
                    {"control_id": "CIS-IOS-1.1.2", "severity": "CRITICAL", "risk_score": 40},
                    {"control_id": "CIS-IOS-1.6.1", "severity": "LOW", "risk_score": 5},
                ],
            }
        ),
    )

    resp = client.get(f"/audit-runs/{RUN_ID}")

    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == RUN_ID
    assert len(body["findings"]) == 2
    # Summary is computed on read, so it can't drift from the stored findings.
    assert body["summary"]["total_findings"] == 2
    assert body["summary"]["compliance_score"] == 55


def test_get_unknown_audit_run_is_404(client, monkeypatch):
    monkeypatch.setattr(main.db, "get_audit_run", AsyncMock(return_value=None))

    resp = client.get(f"/audit-runs/{RUN_ID}")

    assert resp.status_code == 404
