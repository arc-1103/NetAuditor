from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
from pydantic import BaseModel

from app import db
from app.executive_report import (
    fleet_score, fleet_score_trend, remediation_action_mix, top_exposed_devices, violations_found_and_resolved,
)
from app.mttr import summarize_mttr
from app.pdf_service import build_json_report, generate_pdf, render_cef, render_html

app = FastAPI(title="netaudit-reporting", version="1.0.0")


class GenerateRequest(BaseModel):
    audit_run_id: str


def _require_evaluated(data: dict) -> None:
    """A run only has trustworthy findings once it's actually been
    evaluated — for any other status, findings is empty because evaluation
    never ran, not because the device is clean. Rendering a report from
    that would show a fabricated 100/100 score, and /reports/generate would
    go on to permanently mark the never-evaluated run COMPLETE."""
    if data["status"] not in {"EVALUATED", "COMPLETE"}:
        raise HTTPException(
            status_code=422,
            detail=f"Audit run has status {data['status']!r}; no evaluated findings exist yet to report on",
        )


@app.get("/health")
async def health():
    return {"status": "ok", "service": "reporting"}


@app.post("/reports/generate")
async def generate(body: GenerateRequest, x_user_id: str | None = Header(default=None)):
    data = await db.get_report_data(body.audit_run_id)
    if data is None:
        raise HTTPException(status_code=404, detail=f"No audit run {body.audit_run_id}")
    _require_evaluated(data)
    path = generate_pdf(body.audit_run_id, data)
    await db.record_report(body.audit_run_id, str(path), x_user_id or "unknown")
    return {
        "audit_run_id": body.audit_run_id,
        "status": "COMPLETE",
        "download_url": f"/api/reports/{body.audit_run_id}/download",
        "preview_url": f"/api/reports/{body.audit_run_id}/preview",
    }


@app.get("/reports/{audit_run_id}/download")
async def download(audit_run_id: str):
    from app.pdf_service import OUTPUT_DIR
    try:
        path = OUTPUT_DIR / f"netaudit-{audit_run_id}.pdf"
        resolved = path.resolve(strict=True)
    except (FileNotFoundError, OSError):
        raise HTTPException(status_code=404, detail="Report has not been generated")
    if resolved.parent != OUTPUT_DIR.resolve():
        raise HTTPException(status_code=400, detail="Invalid audit run id")
    return FileResponse(resolved, media_type="application/pdf", filename=resolved.name)


@app.get("/reports/{audit_run_id}/preview", response_class=HTMLResponse)
async def preview(audit_run_id: str):
    data = await db.get_report_data(audit_run_id)
    if data is None:
        raise HTTPException(status_code=404, detail=f"No audit run {audit_run_id}")
    _require_evaluated(data)
    return HTMLResponse(render_html(data))


@app.get("/reports/{audit_run_id}/json")
async def json_export(audit_run_id: str):
    data = await db.get_report_data(audit_run_id)
    if data is None:
        raise HTTPException(status_code=404, detail=f"No audit run {audit_run_id}")
    _require_evaluated(data)
    return build_json_report(data)


@app.get("/mttr")
async def mttr():
    """docs/Additional-Features.md §5 — mean-time-to-remediate by severity
    tier, computed live from ledger_events. See app/mttr.py."""
    events = await db.get_ledger_events(("VIOLATION_DETECTED", "APPROVED"))
    return summarize_mttr(events)


@app.get("/executive-report")
async def executive_report():
    """docs/Additional-Features.md §6 — the artifact a non-technical
    stakeholder can read: fleet score + trend, top-5 exposure, violations
    found/resolved, remediation action mix, MTTR by tier. See
    app/executive_report.py; the per-finding provenance chain it also asks
    for is GET /provenance/{run_id}/{control_id} below, linked by finding ID
    rather than embedded here."""
    inputs = await db.get_fleet_report_inputs()
    mttr_events = await db.get_ledger_events(("VIOLATION_DETECTED", "APPROVED"))
    return {
        "fleet_score": fleet_score(inputs["findings_by_run"]),
        "fleet_score_trend": fleet_score_trend(inputs["evaluations"]),
        "top_exposed_devices": top_exposed_devices(inputs["findings_by_run"], inputs["run_metadata"]),
        "violations": violations_found_and_resolved(inputs["violation_events"], inputs["findings_by_run"]),
        "remediation_action_mix": remediation_action_mix(inputs["proposals"]),
        "mttr": summarize_mttr(mttr_events),
    }


@app.get("/provenance/{audit_run_id}/{control_id}")
async def provenance(audit_run_id: str, control_id: str):
    """docs/Additional-Features.md §6 / docs/Suggestions.md item 5: "full
    provenance chain for any single finding, linked by ID". See
    app/db.get_provenance_chain."""
    return await db.get_provenance_chain(audit_run_id, control_id)


@app.get("/reports/{audit_run_id}/cef", response_class=PlainTextResponse)
async def cef_export(audit_run_id: str):
    data = await db.get_report_data(audit_run_id)
    if data is None:
        raise HTTPException(status_code=404, detail=f"No audit run {audit_run_id}")
    _require_evaluated(data)
    return PlainTextResponse(
        render_cef(data),
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="netaudit-{audit_run_id}.cef"'},
    )
