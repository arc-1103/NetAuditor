from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
from pydantic import BaseModel

from app import db
from app.pdf_service import build_json_report, generate_pdf, render_cef, render_html

app = FastAPI(title="netaudit-reporting", version="1.0.0")


class GenerateRequest(BaseModel):
    audit_run_id: str


@app.get("/health")
async def health():
    return {"status": "ok", "service": "reporting"}


@app.post("/reports/generate")
async def generate(body: GenerateRequest, x_user_id: str | None = Header(default=None)):
    data = await db.get_report_data(body.audit_run_id)
    if data is None:
        raise HTTPException(status_code=404, detail=f"No audit run {body.audit_run_id}")
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
    return HTMLResponse(render_html(data))


@app.get("/reports/{audit_run_id}/json")
async def json_export(audit_run_id: str):
    data = await db.get_report_data(audit_run_id)
    if data is None:
        raise HTTPException(status_code=404, detail=f"No audit run {audit_run_id}")
    return build_json_report(data)


@app.get("/reports/{audit_run_id}/cef", response_class=PlainTextResponse)
async def cef_export(audit_run_id: str):
    data = await db.get_report_data(audit_run_id)
    if data is None:
        raise HTTPException(status_code=404, detail=f"No audit run {audit_run_id}")
    return PlainTextResponse(
        render_cef(data),
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="netaudit-{audit_run_id}.cef"'},
    )
