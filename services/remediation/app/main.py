from fastapi import FastAPI, Header, HTTPException

from app import db
from app.batfish_client import preflight
from app.models import ApprovalRequest, GenerateRequest, RemediationProposal
from app.template_engine import RemediationTemplateError, available_templates, render_template

app = FastAPI(title="netaudit-remediation", version="1.0.0")


@app.get("/health")
async def health():
    return {"status": "ok", "service": "remediation", "templates": len(available_templates())}


@app.post("/remediation/generate", response_model=RemediationProposal)
async def generate(body: GenerateRequest):
    try:
        script = render_template(body.finding.remediation, {**body.device, **body.variables})
    except RemediationTemplateError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    result = await preflight(script)
    proposal = RemediationProposal(
        audit_run_id=body.audit_run_id,
        control_id=body.finding.control_id,
        template_name=body.finding.remediation,
        script=script,
        preflight=result,
    )
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
