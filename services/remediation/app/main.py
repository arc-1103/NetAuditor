import os

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from app import db, decision, webhooks
from app.approval_matrix import ApprovalDenied
from app.batfish_client import preflight
from app.manual_provider import EmptyRemediationManualProvider, LearningRemediationManualProvider, RemediationManualProvider
from app.models import ApprovalRequest, Decision, GenerateRequest, PreflightResult, RemediationProposal
from app.rag_remediation import RemediationSynthesisError, synthesize_remediation
from app.slm_client import OllamaSLMClient
from app.template_engine import RemediationTemplateError, available_templates, render_template

app = FastAPI(title="netaudit-remediation", version="1.0.0")

LEARNING_URL = os.getenv("LEARNING_URL")
_manual_provider: RemediationManualProvider = (
    LearningRemediationManualProvider(LEARNING_URL) if LEARNING_URL else EmptyRemediationManualProvider()
)
_slm = OllamaSLMClient(
    os.getenv("OLLAMA_HOST", "http://ollama:11434"),
    os.getenv("OLLAMA_MODEL", "qwen2.5:7b-instruct-q4_K_M"),
    # Defaults to false, unlike Parsing's USE_MOCK_SLM: Parsing's mock
    # extracts real values from the real input text, but this service's
    # mock (app/slm_client.py) returns a fixed placeholder string
    # regardless of the finding. Persisting that placeholder as a real,
    # operator-facing remediation proposal in the default stack would be
    # actively misleading — an unconfigured Ollama should fail the request
    # (502) loudly, not silently produce fake CLI.
    mock=os.getenv("USE_MOCK_SLM", "false").lower() == "true",
)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "remediation", "templates": len(available_templates())}


#: Always present on an agentic-RAG proposal's risk_flags, regardless of how
#: well-grounded the synthesis was. db.approve() only accepts approved=true
#: when preflight_status == 'SAFE', so this flag (via the forced RISK_FLAGS
#: below) makes an agentic-RAG proposal permanently un-approvable through
#: the normal flow — it can only be read, manually verified against the
#: real vendor docs, and applied out-of-band, or rejected. It never earns
#: the same SAFE label a human-reviewed template does.
AGENTIC_RAG_MANUAL_VERIFICATION_FLAG = (
    "Agentic RAG-generated remediation requires manual verification — never directly approvable"
)


async def _resolve_parser_agreement(audit_run_id: str) -> float | None:
    """docs/action.md Phase 2: prefers the real parser_agreement
    (independent TextFSM-vs-SLM agreement,
    services/parsing/app/agreement.py) over the parsing_confidence proxy
    decision_table.yaml used before that landed. Falls back to
    parsing_confidence only when parser_agreement is None (Parsing's
    deterministic extractor doesn't cover this device's vendor yet) — so a
    device outside that coverage degrades to the old behavior rather than
    reading as a confidence of 0 and getting blocked outright."""
    parser_agreement = await db.get_run_parser_agreement(audit_run_id)
    if parser_agreement is None:
        parser_agreement = await db.get_run_parsing_confidence(audit_run_id)
    return parser_agreement


async def _decide(audit_run_id: str, finding) -> Decision:
    """docs/Additional-Features.md §2: classify every proposal against the
    confidence-weighted decision table, regardless of which path built it —
    an agentic-RAG proposal is already forced to RISK_FLAGS/un-approvable,
    but it still gets a citable classification for the ledger."""
    result = decision.decide(
        parser_agreement=await _resolve_parser_agreement(audit_run_id),
        blast_radius=decision.blast_radius_count(finding.blast_radius),
        severity=finding.severity,
    )
    return Decision(**result)


async def _build_proposal(audit_run_id: str, finding, device: dict, variables: dict) -> RemediationProposal:
    """Deterministic template path when a template exists; otherwise the
    agentic RAG fallback (app/rag_remediation.py) for a vendor with no
    committed .j2 template. See README.md's Safety Model section — the
    template path is untouched by this fallback, and the fallback's output
    can never reach the same SAFE preflight verdict a template earns."""
    if finding.remediation is not None:
        try:
            script = render_template(finding.remediation, {**device, **variables})
        except RemediationTemplateError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return RemediationProposal(
            audit_run_id=audit_run_id,
            control_id=finding.control_id,
            template_name=finding.remediation,
            script=script,
            source="template",
            preflight=await preflight(script),
            decision=await _decide(audit_run_id, finding),
        )

    vendor = device.get("detected_vendor") or device.get("vendor")
    if not vendor:
        raise HTTPException(
            status_code=422,
            detail=(
                "No remediation template for this control, and no device vendor was "
                "supplied for the agentic RAG fallback"
            ),
        )
    os_name = device.get("detected_os") or device.get("os")
    try:
        result = await synthesize_remediation(
            vendor=vendor,
            os_name=os_name,
            control_id=finding.control_id,
            title=finding.title,
            evidence=finding.evidence,
            manual_provider=_manual_provider,
            slm_client=_slm,
        )
    except RemediationSynthesisError as exc:
        raise HTTPException(
            status_code=502, detail=f"Agentic RAG remediation synthesis failed: {exc}"
        ) from exc

    static_flags = (await preflight(result.remediation_cli)).risk_flags
    risk_flags = [AGENTIC_RAG_MANUAL_VERIFICATION_FLAG, *static_flags]
    if not result.grounded:
        risk_flags.append("No vendor manual context found — SLM-generated commands are ungrounded")
    if not result.rollback_cli:
        risk_flags.append("SLM did not produce a mandatory rollback script")

    return RemediationProposal(
        audit_run_id=audit_run_id,
        control_id=finding.control_id,
        template_name=f"agentic-rag:{vendor}:{finding.control_id}",
        script=result.remediation_cli,
        rollback_script=result.rollback_cli,
        source="agentic_rag",
        # Fixed at RISK_FLAGS, never SAFE — see AGENTIC_RAG_MANUAL_VERIFICATION_FLAG.
        preflight=PreflightResult(status="RISK_FLAGS", risk_flags=risk_flags, engine="agentic-rag"),
        decision=await _decide(audit_run_id, finding),
    )


@app.post("/remediation/generate", response_model=RemediationProposal)
async def generate(body: GenerateRequest):
    proposal = await _build_proposal(body.audit_run_id, body.finding, body.device, body.variables)
    await db.save_proposal(proposal.model_dump())
    await webhooks.dispatch("REMEDIATION_PROPOSED", {
        "audit_run_id": proposal.audit_run_id, "control_id": proposal.control_id,
        "source": proposal.source, "preflight_status": proposal.preflight.status,
    })
    return proposal


@app.get("/remediation/audit-runs/{audit_run_id}")
async def list_for_run(audit_run_id: str):
    return {"audit_run_id": audit_run_id, "remediations": await db.get_proposals(audit_run_id)}


@app.post("/remediation/audit-runs/{audit_run_id}/generate")
async def generate_for_run(audit_run_id: str):
    """Render every remediation named by this run's compliance findings."""
    findings = await db.get_findings(audit_run_id)
    if not findings:
        raise HTTPException(status_code=404, detail="No remediable findings found for this audit run")
    parser_agreement = await _resolve_parser_agreement(audit_run_id)
    proposals = []
    for finding in findings:
        try:
            script = render_template(finding["remediation"])
        except RemediationTemplateError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        decision_result = Decision(**decision.decide(
            parser_agreement=parser_agreement,
            blast_radius=decision.blast_radius_count(finding.get("blast_radius")),
            severity=finding["severity"],
        ))
        proposal = RemediationProposal(
            audit_run_id=audit_run_id,
            control_id=finding["control_id"],
            template_name=finding["remediation"],
            script=script,
            preflight=await preflight(script),
            decision=decision_result,
        )
        await db.save_proposal(proposal.model_dump())
        proposals.append(proposal)
    return {"audit_run_id": audit_run_id, "generated": len(proposals), "remediations": proposals}


@app.post("/remediation/{control_id}/approve")
async def approve(
    control_id: str,
    body: ApprovalRequest,
    x_user_id: str | None = Header(default=None),
    x_user_role: str | None = Header(default=None),
    x_actor_type: str | None = Header(default=None),
):
    """docs/Additional-Features.md §7: role-scoped approval on top of §2's
    preflight/decision gates. x_user_role comes from the gateway (JWT's own
    role claim — see gateway/app/auth.py) the same way x_user_id already
    does; a caller that omits it (a direct, unauthenticated hop within the
    trusted network — see gateway's own comment on this same header
    pattern) gets treated as the least-privileged role, not the most.

    docs/Suggestions.md item 1 (Agent Firewall): x_actor_type is the same
    kind of trusted-network-internal header — defaults to "human" so every
    existing caller (the gateway never sends this header today) is
    unaffected, but any caller that identifies itself as anything else
    ("ai", "agent", ...) is hard-rejected by approval_matrix.check_permission
    regardless of role. This is a boundary for an AI/automation caller to
    declare itself, not a way to detect one that lies — see
    approval_matrix.check_permission's docstring."""
    if not body.audit_run_id:
        raise HTTPException(status_code=422, detail="audit_run_id is required to identify the proposal")
    try:
        result = await db.approve(
            control_id, body.audit_run_id, body.approved, x_user_id or "unknown", body.comment,
            x_user_role or "auditor", x_actor_type or "human",
        )
    except ApprovalDenied as exc:
        raise HTTPException(status_code=403, detail=exc.reason) from exc
    if result is None:
        raise HTTPException(
            status_code=409,
            detail="Proposal not found, or approval is blocked because preflight is not SAFE",
        )
    # docs/Additional-Features.md §8: "on human approval/rejection -> POST
    # status update" — only once it's a final decision, not a partial
    # dual-approval still awaiting its second signature.
    if result["approval_status"] in ("APPROVED", "REJECTED"):
        await webhooks.dispatch(result["approval_status"], {
            "audit_run_id": result["audit_run_id"], "control_id": result["control_id"],
            "approved_by": result.get("approved_by"), "comment": result.get("approval_comment"),
        })
    return result


class AuditRunScopedRequest(BaseModel):
    audit_run_id: str


class RollbackRequest(BaseModel):
    audit_run_id: str
    reason: str = Field(..., max_length=1000)
    verification_failed: bool = False


@app.post("/remediation/{control_id}/apply")
async def mark_applied(
    control_id: str,
    body: AuditRunScopedRequest,
    x_user_id: str | None = Header(default=None),
):
    """docs/Additional-Features.md §3: Approved -> Applied. Records that an
    operator ran the approved script — see app/db.mark_applied for why this
    isn't a live device push."""
    result = await db.mark_applied(control_id, body.audit_run_id, x_user_id or "unknown")
    if result is None:
        raise HTTPException(status_code=409, detail="Proposal not found, or it isn't APPROVED yet")
    return result


@app.post("/remediation/{control_id}/rollback")
async def trigger_rollback(
    control_id: str,
    body: RollbackRequest,
    x_user_id: str | None = Header(default=None),
):
    """docs/Additional-Features.md §3: restore against the pre-change
    snapshot pinned at approval time, logged with the same provenance
    fields as the original action — see app/db.rollback."""
    result = await db.rollback(control_id, body.audit_run_id, x_user_id or "unknown", body.reason, body.verification_failed)
    if result is None:
        raise HTTPException(status_code=409, detail="Proposal not found, or it was never marked APPLIED")
    # docs/Additional-Features.md §8: "on rollback triggered -> POST
    # high-priority alert".
    await webhooks.dispatch("ROLLED_BACK", {
        "audit_run_id": body.audit_run_id, "control_id": control_id, "reason": body.reason, "priority": "high",
    })
    return result
