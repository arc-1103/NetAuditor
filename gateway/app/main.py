"""
Gateway entrypoint — single entry point for the frontend, routes to every
other service. Route table (source of truth): /contracts/api_gateway_routes.md
Run: uvicorn app.main:app --reload --port 8000
"""
import os
import httpx
from fastapi import FastAPI, UploadFile, File, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from app.auth import get_current_user, authenticate_user, issue_token
from app.db import get_session

app = FastAPI(title="netaudit-gateway")

INGESTION_URL = os.getenv("INGESTION_URL", "http://ingestion:8001")
COMPLIANCE_URL = os.getenv("COMPLIANCE_URL", "http://compliance:8002")
LEARNING_URL = os.getenv("LEARNING_URL", "http://learning:8003")
REMEDIATION_URL = os.getenv("REMEDIATION_URL", "http://remediation:8004")
REPORTING_URL = os.getenv("REPORTING_URL", "http://reporting:8005")


class LoginRequest(BaseModel):
    email: str
    password: str


class ReportGenerateRequest(BaseModel):
    audit_run_id: str


class LearningMapRequest(BaseModel):
    block_id: str
    cli_pattern: str
    field: str
    value: str


class RemediationApproveRequest(BaseModel):
    approved: bool
    comment: str | None = None


@app.get("/health")
async def health():
    return {"status": "ok", "service": "gateway"}


@app.post("/api/login")
async def login(body: LoginRequest, session: AsyncSession = Depends(get_session)):
    user = await authenticate_user(body.email, body.password, session)
    token = issue_token(user)
    return {"access_token": token, "token_type": "bearer", "user": user}


@app.post("/api/upload")
async def upload(file: UploadFile = File(...), user=Depends(get_current_user)):
    async with httpx.AsyncClient() as client:
        files = {"file": (file.filename, await file.read(), file.content_type)}
        # Internal hop is unauthenticated (trusted network) — the user's
        # identity is forwarded explicitly so Ingestion can attribute the
        # AuditRun instead of relying on a shared trust boundary.
        headers = {"X-User-Id": user["sub"], "X-User-Email": user.get("email", "")}
        resp = await client.post(f"{INGESTION_URL}/upload", files=files, headers=headers)
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=resp.text)
    return resp.json()


@app.get("/api/audit-runs/{run_id}")
async def get_audit_run(run_id: str, user=Depends(get_current_user)):
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{COMPLIANCE_URL}/audit-runs/{run_id}")
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=resp.text)
    return resp.json()

@app.post("/api/reports/generate")
async def generate_report(body: ReportGenerateRequest, user=Depends(get_current_user)):
    # Blueprint §3.1: Admin->>GW: POST /api/reports/generate (audit_run_id)
    async with httpx.AsyncClient() as client:
        headers = {"X-User-Id": user["sub"]}
        resp = await client.post(
            f"{REPORTING_URL}/reports/generate", json=body.model_dump(), headers=headers
        )
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=resp.text)
    return resp.json()


@app.get("/api/learning/queue")
async def get_learning_queue(user=Depends(get_current_user)):
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{LEARNING_URL}/learning/queue")
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=resp.text)
    return resp.json()


@app.post("/api/learning/map")
async def submit_learning_map(body: LearningMapRequest, user=Depends(get_current_user)):
    # Blueprint §3.2: admin maps an unrecognized CLI pattern to a
    # SecurityBaseline field/value; Learning lane persists it with the
    # submitting admin's id for the confirmed-mapping record.
    async with httpx.AsyncClient() as client:
        headers = {"X-User-Id": user["sub"]}
        resp = await client.post(
            f"{LEARNING_URL}/learning/map", json=body.model_dump(), headers=headers
        )
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=resp.text)
    return resp.json()


@app.post("/api/remediation/{control_id}/approve")
async def approve_remediation(
    control_id: str, body: RemediationApproveRequest, user=Depends(get_current_user)
):
    async with httpx.AsyncClient() as client:
        headers = {"X-User-Id": user["sub"]}
        resp = await client.post(
            f"{REMEDIATION_URL}/remediation/{control_id}/approve",
            json=body.model_dump(),
            headers=headers,
        )
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=resp.text)
    return resp.json()
