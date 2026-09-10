import os

from fastapi import FastAPI, Header, HTTPException

from app import db
from app.batfish_client import preflight
from app.manual_provider import EmptyRemediationManualProvider, LearningRemediationManualProvider, RemediationManualProvider
from app.models import ApprovalRequest, GenerateRequest, PreflightResult, RemediationProposal
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
    )


@app.post("/remediation/generate", response_model=RemediationProposal)
async def generate(body: GenerateRequest):
    proposal = await _build_proposal(body.audit_run_id, body.finding, body.device, body.variables)
    await db.save_proposal(proposal.model_dump())
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
    proposals = []
    for finding in findings:
        try:
            script = render_template(finding["remediation"])
        except RemediationTemplateError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        proposal = RemediationProposal(
            audit_run_id=audit_run_id,
            control_id=finding["control_id"],
            template_name=finding["remediation"],
            script=script,
            preflight=await preflight(script),
        )
        await db.save_proposal(proposal.model_dump())
        proposals.append(proposal)
    return {"audit_run_id": audit_run_id, "generated": len(proposals), "remediations": proposals}


@app.post("/remediation/{control_id}/approve")
async def approve(
    control_id: str,
    body: ApprovalRequest,
    x_user_id: str | None = Header(default=None),
):
    if not body.audit_run_id:
        raise HTTPException(status_code=422, detail="audit_run_id is required to identify the proposal")
    result = await db.approve(control_id, body.audit_run_id, body.approved, x_user_id or "unknown", body.comment)
    if result is None:
        raise HTTPException(
            status_code=409,
            detail="Proposal not found, or approval is blocked because preflight is not SAFE",
        )
    return result
