"""
Gateway entrypoint — single entry point for the frontend, routes to every
other service. Route table (source of truth): /contracts/api_gateway_routes.md
Run: uvicorn app.main:app --reload --port 8000
"""
import os
import json
import logging
import time
import uuid
from collections import defaultdict, deque
import httpx
from fastapi import FastAPI, UploadFile, File, Depends, HTTPException, Request
from fastapi.responses import Response, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
from app.auth import (
    get_current_user, authenticate_user, issue_token, require_admin,
    require_operator, require_reader, validate_runtime_secret,
)
from app.db import get_session

app = FastAPI(title="netaudit-gateway")
logger = logging.getLogger("netaudit.gateway")
UPSTREAM_TIMEOUT = httpx.Timeout(float(os.getenv("UPSTREAM_TIMEOUT_SECONDS", "30")), connect=5.0)
MAX_UPLOAD_SIZE_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", "10"))
RATE_LIMIT_PER_MIN = int(os.getenv("RATE_LIMIT_PER_MIN", "120"))
_request_windows: dict[str, deque[float]] = defaultdict(deque)
CORS_ORIGINS = [origin.strip() for origin in os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


class OperationalMiddleware:
    """Pure ASGI request IDs, access logging and bounded per-client rate limiting."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope.get("headers", []))
        request_id = headers.get(b"x-request-id", str(uuid.uuid4()).encode()).decode(errors="replace")
        path = scope.get("path", "")
        client = scope.get("client")
        if RATE_LIMIT_PER_MIN > 0 and path.startswith("/api/"):
            key = client[0] if client else "unknown"
            now = time.monotonic()
            window = _request_windows[key]
            while window and window[0] <= now - 60:
                window.popleft()
            if len(window) >= RATE_LIMIT_PER_MIN:
                response = JSONResponse({"detail": "Rate limit exceeded"}, status_code=429, headers={"Retry-After": "60", "X-Request-Id": request_id})
                return await response(scope, receive, send)
            window.append(now)
        started = time.monotonic()
        status = 500

        async def send_with_context(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                message.setdefault("headers", []).append((b"x-request-id", request_id.encode()))
            await send(message)

        try:
            await self.app(scope, receive, send_with_context)
        finally:
            logger.info(json.dumps({"request_id": request_id, "method": scope.get("method"), "path": path, "status": status, "duration_ms": round((time.monotonic() - started) * 1000, 2)}))


app.add_middleware(OperationalMiddleware)


@app.on_event("startup")
async def validate_configuration() -> None:
    validate_runtime_secret()


def upstream_error(response: httpx.Response) -> HTTPException:
    try:
        payload = response.json()
        detail = payload.get("detail", payload) if isinstance(payload, dict) else payload
    except (ValueError, json.JSONDecodeError):
        detail = "Upstream service request failed"
    return HTTPException(status_code=response.status_code, detail=detail)

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
    # Optional at the gateway for backward compatibility; the remediation
    # service returns a clear 422 when an ambiguous approval omits it.
    audit_run_id: str | None = None
    comment: str | None = None


class RemediationGenerateRequest(BaseModel):
    audit_run_id: str
    finding: dict
    device: dict = Field(default_factory=dict)
    variables: dict = Field(default_factory=dict)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "gateway"}


@app.post("/api/login")
async def login(body: LoginRequest, session: AsyncSession = Depends(get_session)):
    user = await authenticate_user(body.email, body.password, session)
    token = issue_token(user)
    return {"access_token": token, "token_type": "bearer", "user": user}


@app.post("/api/upload")
async def upload(request: Request, file: UploadFile = File(...), user=Depends(require_operator)):
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            too_large = int(content_length) > MAX_UPLOAD_SIZE_MB * 1024 * 1024 + 64 * 1024
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid Content-Length header")
        if too_large:
            raise HTTPException(status_code=413, detail=f"Upload exceeds {MAX_UPLOAD_SIZE_MB} MB limit")
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        # Forward the spooled file instead of copying the entire configuration
        # into gateway memory. Ingestion enforces the bounded byte count.
        await file.seek(0)
        files = {"file": (file.filename, file.file, file.content_type)}
        # Internal hop is unauthenticated (trusted network) — the user's
        # identity is forwarded explicitly so Ingestion can attribute the
        # AuditRun instead of relying on a shared trust boundary.
        headers = {"X-User-Id": user["sub"], "X-User-Email": user.get("email", "")}
        resp = await client.post(f"{INGESTION_URL}/upload", files=files, headers=headers)
    if resp.status_code >= 400:
        raise upstream_error(resp)
    return resp.json()


@app.get("/api/audit-runs/{run_id}")
async def get_audit_run(run_id: str, user=Depends(require_reader)):
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        resp = await client.get(f"{COMPLIANCE_URL}/audit-runs/{run_id}")
    if resp.status_code >= 400:
        raise upstream_error(resp)
    return resp.json()

@app.post("/api/reports/generate")
async def generate_report(body: ReportGenerateRequest, user=Depends(require_reader)):
    # Blueprint §3.1: Admin->>GW: POST /api/reports/generate (audit_run_id)
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        headers = {"X-User-Id": user["sub"]}
        resp = await client.post(
            f"{REPORTING_URL}/reports/generate", json=body.model_dump(), headers=headers
        )
    if resp.status_code >= 400:
        raise upstream_error(resp)
    return resp.json()


@app.get("/api/learning/queue")
async def get_learning_queue(user=Depends(require_admin)):
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        resp = await client.get(f"{LEARNING_URL}/learning/queue")
    if resp.status_code >= 400:
        raise upstream_error(resp)
    return resp.json()


@app.post("/api/learning/map")
async def submit_learning_map(body: LearningMapRequest, user=Depends(require_admin)):
    # Blueprint §3.2: admin maps an unrecognized CLI pattern to a
    # SecurityBaseline field/value; Learning lane persists it with the
    # submitting admin's id for the confirmed-mapping record.
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        headers = {"X-User-Id": user["sub"]}
        resp = await client.post(
            f"{LEARNING_URL}/learning/map", json=body.model_dump(), headers=headers
        )
    if resp.status_code >= 400:
        raise upstream_error(resp)
    return resp.json()


@app.post("/api/remediation/{control_id}/approve")
async def approve_remediation(
    control_id: str, body: RemediationApproveRequest, user=Depends(require_operator)
):
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        headers = {"X-User-Id": user["sub"]}
        resp = await client.post(
            f"{REMEDIATION_URL}/remediation/{control_id}/approve",
            json=body.model_dump(exclude_none=True),
            headers=headers,
        )
    if resp.status_code >= 400:
        raise upstream_error(resp)
    return resp.json()


@app.post("/api/remediation/generate")
async def generate_remediation(body: RemediationGenerateRequest, user=Depends(require_operator)):
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        resp = await client.post(
            f"{REMEDIATION_URL}/remediation/generate",
            json=body.model_dump(),
            headers={"X-User-Id": user["sub"]},
        )
    if resp.status_code >= 400:
        raise upstream_error(resp)
    return resp.json()


@app.get("/api/remediation/audit-runs/{run_id}")
async def list_remediations(run_id: str, user=Depends(require_reader)):
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        resp = await client.get(f"{REMEDIATION_URL}/remediation/audit-runs/{run_id}")
    if resp.status_code >= 400:
        raise upstream_error(resp)
    return resp.json()


@app.post("/api/remediation/audit-runs/{run_id}/generate")
async def generate_run_remediations(run_id: str, user=Depends(require_operator)):
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        resp = await client.post(
            f"{REMEDIATION_URL}/remediation/audit-runs/{run_id}/generate",
            headers={"X-User-Id": user["sub"]},
        )
    if resp.status_code >= 400:
        raise upstream_error(resp)
    return resp.json()


@app.get("/api/reports/{run_id}/download")
async def download_report(run_id: str, user=Depends(require_reader)):
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        resp = await client.get(f"{REPORTING_URL}/reports/{run_id}/download")
    if resp.status_code >= 400:
        raise upstream_error(resp)
    disposition = resp.headers.get("content-disposition", f'attachment; filename="netaudit-{run_id}.pdf"')
    return Response(resp.content, media_type="application/pdf", headers={"Content-Disposition": disposition})


@app.get("/api/reports/{run_id}/preview")
async def preview_report(run_id: str, user=Depends(require_reader)):
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        resp = await client.get(f"{REPORTING_URL}/reports/{run_id}/preview")
    if resp.status_code >= 400:
        raise upstream_error(resp)
    return Response(resp.content, media_type="text/html")


@app.get("/api/reports/{run_id}/json")
async def json_report(run_id: str, user=Depends(require_reader)):
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        resp = await client.get(f"{REPORTING_URL}/reports/{run_id}/json")
    if resp.status_code >= 400:
        raise upstream_error(resp)
    return resp.json()


@app.get("/api/reports/{run_id}/cef")
async def cef_report(run_id: str, user=Depends(require_reader)):
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        resp = await client.get(f"{REPORTING_URL}/reports/{run_id}/cef")
    if resp.status_code >= 400:
        raise upstream_error(resp)
    return Response(
        resp.content,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="netaudit-{run_id}.cef"'},
    )
