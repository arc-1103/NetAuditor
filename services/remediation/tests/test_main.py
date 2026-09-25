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


def test_slm_defaults_to_real_mode_not_mock():
    """USE_MOCK_SLM defaults to false, unlike Parsing's: this service's mock
    is a fixed placeholder string with no relation to the finding, and
    persisting it as a real operator-facing proposal would be actively
    misleading. An unconfigured Ollama must fail the request (502), not
    silently produce fake CLI."""
    assert main._slm.mock is False


@pytest.mark.asyncio
async def test_generate_renders_preflights_and_persists(monkeypatch):
    save = AsyncMock()
    monkeypatch.setattr(main.db, "save_proposal", save)
    monkeypatch.setattr(main.db, "get_run_parsing_confidence", AsyncMock(return_value=0.99))
    response = await request("POST", "/remediation/generate", json={"audit_run_id": RUN_ID, "finding": FINDING})
    assert response.status_code == 200
    assert response.json()["preflight"]["status"] == "SAFE"
    assert "ip ssh version 2" in response.json()["script"]
    assert response.json()["decision"]["ruleset_version"] == "1.0.0"
    save.assert_awaited_once()


@pytest.mark.asyncio
async def test_generate_dispatches_a_remediation_proposed_webhook(monkeypatch):
    monkeypatch.setattr(main.db, "save_proposal", AsyncMock())
    monkeypatch.setattr(main.db, "get_run_parsing_confidence", AsyncMock(return_value=0.99))
    dispatch = AsyncMock()
    monkeypatch.setattr(main.webhooks, "dispatch", dispatch)

    await request("POST", "/remediation/generate", json={"audit_run_id": RUN_ID, "finding": FINDING})

    dispatch.assert_awaited_once()
    event_type, payload = dispatch.await_args.args
    assert event_type == "REMEDIATION_PROPOSED"
    assert payload["control_id"] == "CIS-IOS-1.1.1"


@pytest.mark.asyncio
async def test_unknown_template_is_422(monkeypatch):
    finding = {**FINDING, "remediation": "not_present.j2"}
    response = await request("POST", "/remediation/generate", json={"audit_run_id": RUN_ID, "finding": finding})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_omitting_the_remediation_key_entirely_is_422_not_silent_agentic_rag():
    """A finding that omits `remediation` outright is a malformed caller,
    not the same signal as an explicit remediation: null (which means "no
    template exists" and legitimately triggers the fallback). Silently
    defaulting a missing key to None would let a client bug trigger
    unrequested SLM synthesis."""
    finding_missing_key = {k: v for k, v in FINDING.items() if k != "remediation"}
    response = await request(
        "POST",
        "/remediation/generate",
        json={
            "audit_run_id": RUN_ID,
            "finding": finding_missing_key,
            "device": {"detected_vendor": "fortinet"},
        },
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_empty_string_remediation_is_a_template_error_not_agentic_rag():
    """Truthiness would route "" into the agentic RAG fallback the same as
    None; it must instead hit the template engine's own validation."""
    finding = {**FINDING, "remediation": ""}
    response = await request(
        "POST",
        "/remediation/generate",
        json={
            "audit_run_id": RUN_ID,
            "finding": finding,
            "device": {"detected_vendor": "fortinet"},
        },
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_approve_requires_run_id():
    response = await request("POST", "/remediation/CIS-IOS-1.1.1/approve", json={"approved": True})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_approve_is_audited(monkeypatch):
    approve = AsyncMock(return_value={"audit_run_id": RUN_ID, "control_id": "CIS-IOS-1.1.1", "approval_status": "APPROVED"})
    monkeypatch.setattr(main.db, "approve", approve)
    response = await request("POST",
        "/remediation/CIS-IOS-1.1.1/approve",
        json={"approved": True, "audit_run_id": RUN_ID, "comment": "CAB-42"},
        headers={"X-User-Id": "admin-1", "X-User-Role": "admin"},
    )
    assert response.status_code == 200
    approve.assert_awaited_once_with("CIS-IOS-1.1.1", RUN_ID, True, "admin-1", "CAB-42", "admin")


@pytest.mark.asyncio
async def test_approve_without_a_role_header_defaults_to_the_least_privileged_role(monkeypatch):
    approve = AsyncMock(return_value={"audit_run_id": RUN_ID, "control_id": "CIS-IOS-1.1.1", "approval_status": "APPROVED"})
    monkeypatch.setattr(main.db, "approve", approve)
    response = await request("POST",
        "/remediation/CIS-IOS-1.1.1/approve",
        json={"approved": True, "audit_run_id": RUN_ID},
        headers={"X-User-Id": "admin-1"},
    )
    assert response.status_code == 200
    approve.assert_awaited_once_with("CIS-IOS-1.1.1", RUN_ID, True, "admin-1", None, "auditor")


@pytest.mark.asyncio
async def test_final_approval_dispatches_a_webhook(monkeypatch):
    monkeypatch.setattr(main.db, "approve", AsyncMock(return_value={
        "audit_run_id": RUN_ID, "control_id": "CIS-IOS-1.1.1", "approval_status": "APPROVED", "approved_by": "admin-1",
    }))
    dispatch = AsyncMock()
    monkeypatch.setattr(main.webhooks, "dispatch", dispatch)

    await request("POST", "/remediation/CIS-IOS-1.1.1/approve", json={"approved": True, "audit_run_id": RUN_ID})

    dispatch.assert_awaited_once()
    assert dispatch.await_args.args[0] == "APPROVED"


@pytest.mark.asyncio
async def test_partial_dual_approval_does_not_dispatch_a_webhook_yet(monkeypatch):
    monkeypatch.setattr(main.db, "approve", AsyncMock(return_value={
        "audit_run_id": RUN_ID, "control_id": "CIS-IOS-1.1.1", "approval_status": "PENDING",
        "dual_approval": {"required": 2, "received": 1},
    }))
    dispatch = AsyncMock()
    monkeypatch.setattr(main.webhooks, "dispatch", dispatch)

    await request("POST", "/remediation/CIS-IOS-1.1.1/approve", json={"approved": True, "audit_run_id": RUN_ID})

    dispatch.assert_not_awaited()


@pytest.mark.asyncio
async def test_non_safe_approval_returns_conflict(monkeypatch):
    monkeypatch.setattr(main.db, "approve", AsyncMock(return_value=None))
    response = await request("POST",
        "/remediation/CIS-IOS-1.1.1/approve",
        json={"approved": True, "audit_run_id": RUN_ID},
    )
    assert response.status_code == 409


@pytest.mark.asyncio
async def test_approval_denied_by_the_role_matrix_is_403(monkeypatch):
    from app.approval_matrix import ApprovalDenied
    monkeypatch.setattr(main.db, "approve", AsyncMock(side_effect=ApprovalDenied("Network Operator cannot approve a HIGH-risk change.")))
    response = await request("POST",
        "/remediation/CIS-IOS-1.1.1/approve",
        json={"approved": True, "audit_run_id": RUN_ID},
        headers={"X-User-Id": "operator-1", "X-User-Role": "operator"},
    )
    assert response.status_code == 403
    assert "HIGH-risk" in response.json()["detail"]


@pytest.mark.asyncio
async def test_bulk_generation_uses_persisted_findings(monkeypatch):
    monkeypatch.setattr(main.db, "get_findings", AsyncMock(return_value=[{**FINDING, "blast_radius": []}]))
    save = AsyncMock()
    monkeypatch.setattr(main.db, "save_proposal", save)
    monkeypatch.setattr(main.db, "get_run_parsing_confidence", AsyncMock(return_value=0.99))
    response = await request("POST", f"/remediation/audit-runs/{RUN_ID}/generate")
    assert response.status_code == 200
    assert response.json()["generated"] == 1
    save.assert_awaited_once()


# ── Agentic RAG fallback (no committed template) ─────────────────────
NO_TEMPLATE_FINDING = {**FINDING, "remediation": None}


class FakeManualProvider:
    def __init__(self, excerpts=None):
        self.excerpts = excerpts or []

    async def lookup(self, vendor, os_name, control_id):
        return self.excerpts


class FakeSLM:
    def __init__(self, response=None):
        self.response = response or {"remediation_cli": "fix it", "rollback_cli": "unfix it"}

    async def synthesize(self, prompt):
        return self.response


@pytest.mark.asyncio
async def test_missing_template_without_a_device_vendor_is_422(monkeypatch):
    save = AsyncMock()
    monkeypatch.setattr(main.db, "save_proposal", save)

    response = await request(
        "POST", "/remediation/generate", json={"audit_run_id": RUN_ID, "finding": NO_TEMPLATE_FINDING}
    )

    assert response.status_code == 422
    save.assert_not_awaited()


@pytest.mark.asyncio
async def test_missing_template_falls_back_to_agentic_rag(monkeypatch):
    save = AsyncMock()
    monkeypatch.setattr(main.db, "save_proposal", save)
    monkeypatch.setattr(main.db, "get_run_parsing_confidence", AsyncMock(return_value=0.99))
    monkeypatch.setattr(main, "_manual_provider", FakeManualProvider(excerpts=["do the thing"]))
    monkeypatch.setattr(main, "_slm", FakeSLM())

    response = await request(
        "POST",
        "/remediation/generate",
        json={
            "audit_run_id": RUN_ID,
            "finding": NO_TEMPLATE_FINDING,
            "device": {"detected_vendor": "fortinet", "detected_os": "FortiOS"},
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["source"] == "agentic_rag"
    assert body["script"] == "fix it"
    assert body["rollback_script"] == "unfix it"
    assert body["template_name"] == "agentic-rag:fortinet:CIS-IOS-1.1.1"
    save.assert_awaited_once()


@pytest.mark.asyncio
async def test_agentic_rag_proposal_is_always_risk_flags_never_safe(monkeypatch):
    """The core safety requirement: even a fully grounded synthesis with a
    rollback, and no static lockout patterns, must never reach SAFE — an
    agentic-RAG proposal can never be approved through the normal flow."""
    monkeypatch.setattr(main.db, "save_proposal", AsyncMock())
    monkeypatch.setattr(main.db, "get_run_parsing_confidence", AsyncMock(return_value=0.99))
    monkeypatch.setattr(main, "_manual_provider", FakeManualProvider(excerpts=["grounded context"]))
    monkeypatch.setattr(main, "_slm", FakeSLM(response={"remediation_cli": "fix it", "rollback_cli": "unfix it"}))

    response = await request(
        "POST",
        "/remediation/generate",
        json={
            "audit_run_id": RUN_ID,
            "finding": NO_TEMPLATE_FINDING,
            "device": {"detected_vendor": "fortinet", "detected_os": "FortiOS"},
        },
    )

    body = response.json()
    assert body["preflight"]["status"] == "RISK_FLAGS"
    assert any("never directly approvable" in flag for flag in body["preflight"]["risk_flags"])


@pytest.mark.asyncio
async def test_agentic_rag_proposal_flags_ungrounded_synthesis_and_missing_rollback(monkeypatch):
    monkeypatch.setattr(main.db, "save_proposal", AsyncMock())
    monkeypatch.setattr(main.db, "get_run_parsing_confidence", AsyncMock(return_value=0.99))
    monkeypatch.setattr(main, "_manual_provider", FakeManualProvider(excerpts=[]))
    monkeypatch.setattr(main, "_slm", FakeSLM(response={"remediation_cli": "fix it", "rollback_cli": ""}))

    response = await request(
        "POST",
        "/remediation/generate",
        json={
            "audit_run_id": RUN_ID,
            "finding": NO_TEMPLATE_FINDING,
            "device": {"detected_vendor": "fortinet"},
        },
    )

    flags = response.json()["preflight"]["risk_flags"]
    assert any("ungrounded" in flag for flag in flags)
    assert any("mandatory rollback" in flag for flag in flags)


# ── Rollback lifecycle (docs/Additional-Features.md §3) ──────────────
@pytest.mark.asyncio
async def test_apply_marks_applied(monkeypatch):
    mark_applied = AsyncMock(return_value={"control_id": "CIS-IOS-1.1.1", "rollback_status": "APPLIED"})
    monkeypatch.setattr(main.db, "mark_applied", mark_applied)
    response = await request(
        "POST", "/remediation/CIS-IOS-1.1.1/apply",
        json={"audit_run_id": RUN_ID}, headers={"X-User-Id": "operator-1"},
    )
    assert response.status_code == 200
    mark_applied.assert_awaited_once_with("CIS-IOS-1.1.1", RUN_ID, "operator-1")


@pytest.mark.asyncio
async def test_apply_of_unapproved_proposal_is_conflict(monkeypatch):
    monkeypatch.setattr(main.db, "mark_applied", AsyncMock(return_value=None))
    response = await request("POST", "/remediation/CIS-IOS-1.1.1/apply", json={"audit_run_id": RUN_ID})
    assert response.status_code == 409


@pytest.mark.asyncio
async def test_rollback_is_audited_with_reason(monkeypatch):
    rollback = AsyncMock(return_value={"control_id": "CIS-IOS-1.1.1", "rollback_status": "ROLLED_BACK"})
    monkeypatch.setattr(main.db, "rollback", rollback)
    response = await request(
        "POST", "/remediation/CIS-IOS-1.1.1/rollback",
        json={"audit_run_id": RUN_ID, "reason": "post-change verification failed", "verification_failed": True},
        headers={"X-User-Id": "operator-1"},
    )
    assert response.status_code == 200
    rollback.assert_awaited_once_with(
        "CIS-IOS-1.1.1", RUN_ID, "operator-1", "post-change verification failed", True
    )


@pytest.mark.asyncio
async def test_rollback_dispatches_a_high_priority_webhook(monkeypatch):
    monkeypatch.setattr(main.db, "rollback", AsyncMock(return_value={"control_id": "CIS-IOS-1.1.1", "rollback_status": "ROLLED_BACK"}))
    dispatch = AsyncMock()
    monkeypatch.setattr(main.webhooks, "dispatch", dispatch)

    await request(
        "POST", "/remediation/CIS-IOS-1.1.1/rollback",
        json={"audit_run_id": RUN_ID, "reason": "broke connectivity"},
    )

    dispatch.assert_awaited_once()
    event_type, payload = dispatch.await_args.args
    assert event_type == "ROLLED_BACK"
    assert payload["priority"] == "high"


@pytest.mark.asyncio
async def test_rollback_of_a_never_applied_proposal_is_conflict(monkeypatch):
    monkeypatch.setattr(main.db, "rollback", AsyncMock(return_value=None))
    response = await request(
        "POST", "/remediation/CIS-IOS-1.1.1/rollback",
        json={"audit_run_id": RUN_ID, "reason": "changed my mind"},
    )
    assert response.status_code == 409
