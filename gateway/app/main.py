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
    AUTH_PROVIDER, keycloak_login,
    get_current_user, authenticate_user, issue_token, require_admin,
    require_operator, require_reader, validate_runtime_secret,
)
from app import service_token
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


# Optional services (e.g. learning in the `advanced` profile) may not be running.
@app.exception_handler(httpx.ConnectError)
async def upstream_unreachable(request: Request, exc: httpx.ConnectError) -> JSONResponse:
    host = exc.request.url.host
    logger.warning("Upstream %s unreachable for %s: %s", host, request.url.path, exc)
    return JSONResponse({"detail": f"{host} service is not running"}, status_code=503)

INGESTION_URL = os.getenv("INGESTION_URL", "http://ingestion:8001")
COMPLIANCE_URL = os.getenv("COMPLIANCE_URL", "http://compliance:8002")
LEARNING_URL = os.getenv("LEARNING_URL", "http://learning:8003")
REMEDIATION_URL = os.getenv("REMEDIATION_URL", "http://remediation:8004")
REPORTING_URL = os.getenv("REPORTING_URL", "http://reporting:8005")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:7b-instruct-q4_K_M")


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
    vendor: str = "unknown"
    os: str | None = None
    access_tier: str = "admin"  # public | admin: who may retrieve this mapping


class ExplainRequest(BaseModel):
    title: str = Field(max_length=500)
    evidence: str = Field(max_length=8000)


class LearningSearchRequest(BaseModel):
    query: str = Field(max_length=8000)
    vendor: str | None = None
    os: str | None = None


class RemediationApproveRequest(BaseModel):
    approved: bool
    # Optional at the gateway for backward compatibility; the remediation
    # service returns a clear 422 when an ambiguous approval omits it.
    audit_run_id: str | None = None
    comment: str | None = None


class RemediationAuditRunScopedRequest(BaseModel):
    audit_run_id: str


class RemediationRollbackRequest(BaseModel):
    audit_run_id: str
    reason: str
    verification_failed: bool = False


class ReachabilityDiffRequest(BaseModel):
    before: dict
    after: dict


class CounterfactualRequest(BaseModel):
    current_baseline: dict
    proposed_baseline: dict
    framework: str | None = None


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
    if AUTH_PROVIDER == "keycloak":
        token, user = await keycloak_login(body.email, body.password)
        return {"access_token": token, "token_type": "bearer", "user": {"id": user["id"], "email": user["email"], "role": user["role"]}}
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


class CollectRequest(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    device_type: str
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256, repr=False)
    port: int = 22
    method: str = "netmiko"


@app.get("/api/time-status")
async def time_status(user=Depends(require_reader)):
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        resp = await client.get(f"{REPORTING_URL}/time-status")
    if resp.status_code >= 400:
        raise upstream_error(resp)
    return resp.json()


@app.post("/api/collect")
async def collect_config(body: CollectRequest, user=Depends(require_operator)):
    """Online ingest (Netmiko/NAPALM). Credentials are forwarded once to
    Ingestion and never stored or logged; Ingestion refuses unless collection
    is enabled and the host is in its allowed networks."""
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        resp = await client.post(
            f"{INGESTION_URL}/collect", json=body.model_dump(),
            headers={"X-User-Id": user["sub"], "X-User-Email": user.get("email", "")},
        )
    if resp.status_code >= 400:
        raise upstream_error(resp)
    return resp.json()


@app.get("/api/audit-runs")
async def list_audit_runs(limit: int = 20, user=Depends(require_reader)):
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        resp = await client.get(f"{COMPLIANCE_URL}/audit-runs", params={"limit": limit})
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


@app.get("/api/audit-runs/{run_id}/trust")
async def get_trust_view(run_id: str, user=Depends(require_reader)):
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        resp = await client.get(f"{COMPLIANCE_URL}/audit-runs/{run_id}/trust")
    if resp.status_code >= 400:
        raise upstream_error(resp)
    return resp.json()

@app.get("/api/audit-runs/{run_id}/counterfactual/{control_id}")
async def simulate_fix(run_id: str, control_id: str, user=Depends(require_reader)):
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        resp = await client.get(f"{COMPLIANCE_URL}/audit-runs/{run_id}/counterfactual/{control_id}")
    if resp.status_code >= 400:
        raise upstream_error(resp)
    return resp.json()


@app.get("/api/audit-runs/{run_id}/history")
async def get_history(run_id: str, user=Depends(require_reader)):
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        resp = await client.get(f"{COMPLIANCE_URL}/audit-runs/{run_id}/history")
    if resp.status_code >= 400:
        raise upstream_error(resp)
    return resp.json()


@app.get("/api/audit-runs/{run_id}/drift/{control_id}")
async def get_drift(run_id: str, control_id: str, user=Depends(require_reader)):
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        resp = await client.get(f"{COMPLIANCE_URL}/audit-runs/{run_id}/drift/{control_id}")
    if resp.status_code >= 400:
        raise upstream_error(resp)
    return resp.json()


async def _compliance_get(path: str):
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        resp = await client.get(f"{COMPLIANCE_URL}{path}")
    if resp.status_code >= 400:
        raise upstream_error(resp)
    return resp.json()


@app.get("/api/topology/fleet")
async def fleet_topology(user=Depends(require_reader)):
    return await _compliance_get("/topology/fleet")


class WaiverRequest(BaseModel):
    audit_run_id: str
    control_id: str
    reason: str = Field(min_length=1, max_length=2000)
    expires_at: str
    ticket: str | None = Field(default=None, max_length=200)


class RevokeRequest(BaseModel):
    reason: str = Field(default="", max_length=2000)


def _who(user: dict) -> dict:
    return {"X-User-Id": user["sub"], "X-User-Email": user.get("email", "")}


@app.get("/api/waivers")
async def list_waivers(status: str | None = None, user=Depends(require_reader)):
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        resp = await client.get(f"{COMPLIANCE_URL}/waivers", params={"status": status} if status else None)
    if resp.status_code >= 400:
        raise upstream_error(resp)
    return resp.json()


@app.post("/api/waivers")
async def grant_waiver(body: WaiverRequest, user=Depends(require_admin)):
    """Admin-only: accept the risk of one failing control until a date. The grant
    is a ledger event attributed to the verified caller."""
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        resp = await client.post(f"{COMPLIANCE_URL}/waivers", json=body.model_dump(), headers=_who(user))
    if resp.status_code >= 400:
        raise upstream_error(resp)
    return resp.json()


@app.post("/api/waivers/{waiver_id}/revoke")
async def revoke_waiver(waiver_id: str, body: RevokeRequest, user=Depends(require_admin)):
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        resp = await client.post(f"{COMPLIANCE_URL}/waivers/{waiver_id}/revoke", json=body.model_dump(), headers=_who(user))
    if resp.status_code >= 400:
        raise upstream_error(resp)
    return resp.json()


@app.get("/api/ledger/status")
async def ledger_status(user=Depends(require_reader)):
    return await _compliance_get("/ledger/status")


@app.get("/api/ledger/verify")
async def ledger_verify(user=Depends(require_reader)):
    return await _compliance_get("/ledger/verify")


@app.get("/api/ledger/proof/{event_id}")
async def ledger_proof(event_id: str, user=Depends(require_reader)):
    return await _compliance_get(f"/ledger/proof/{event_id}")


@app.post("/api/ledger/seal")
async def ledger_seal(user=Depends(require_admin)):
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        resp = await client.post(f"{COMPLIANCE_URL}/ledger/seal")
    if resp.status_code >= 400:
        raise upstream_error(resp)
    return resp.json()


@app.get("/api/audit-runs/{run_id}/topology")
async def get_topology(run_id: str, user=Depends(require_reader)):
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        resp = await client.get(f"{COMPLIANCE_URL}/audit-runs/{run_id}/topology")
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


@app.post("/api/explain")
async def explain_finding(body: ExplainRequest, user=Depends(require_reader)):
    # Plain-language explanation only; the verdict stays with OPA.
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        resp = await client.post(f"{OLLAMA_URL}/v1/chat/completions", json={
            "model": OLLAMA_MODEL,
            "temperature": 0,
            "max_tokens": 100,
            "messages": [
                {"role": "system", "content": "Explain network security findings in two short, non-technical sentences. Do not invent facts."},
                {"role": "user", "content": f"Finding: {body.title}\nEvidence: {body.evidence}"},
            ],
        })
    if resp.status_code >= 400:
        raise upstream_error(resp)
    answer = (resp.json().get("choices") or [{}])[0].get("message", {}).get("content", "").strip()
    if not answer:
        raise HTTPException(status_code=502, detail="Model returned no explanation")
    return {"answer": answer}


@app.get("/api/learning/queue")
async def get_learning_queue(user=Depends(require_admin)):
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT, headers=service_token.auth_headers("gateway", user["sub"], user["role"])) as client:
        resp = await client.get(f"{LEARNING_URL}/learning/queue")
    if resp.status_code >= 400:
        raise upstream_error(resp)
    return resp.json()


@app.get("/api/learning/queue/{block_id}/similar")
async def get_learning_similar(block_id: str, user=Depends(require_admin)):
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT, headers=service_token.auth_headers("gateway", user["sub"], user["role"])) as client:
        resp = await client.get(f"{LEARNING_URL}/learning/queue/{block_id}/similar")
    if resp.status_code >= 400:
        raise upstream_error(resp)
    return resp.json()


@app.post("/api/learning/search")
async def search_learning_mappings(body: LearningSearchRequest, user=Depends(require_reader)):
    # The caller's role travels to the index, which filters on it before ranking.
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT, headers=service_token.auth_headers("gateway", user["sub"], user["role"])) as client:
        resp = await client.post(f"{LEARNING_URL}/learning/search", json=body.model_dump())
    if resp.status_code >= 400:
        raise upstream_error(resp)
    return resp.json()


@app.post("/api/learning/map")
async def submit_learning_map(body: LearningMapRequest, user=Depends(require_admin)):
    # Blueprint §3.2: admin maps an unrecognized CLI pattern to a
    # SecurityBaseline field/value; Learning lane persists it with the
    # submitting admin's id for the confirmed-mapping record.
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT, headers=service_token.auth_headers("gateway", user["sub"], user["role"])) as client:
        resp = await client.post(f"{LEARNING_URL}/learning/map", json=body.model_dump())
    if resp.status_code >= 400:
        raise upstream_error(resp)
    return resp.json()


@app.post("/api/remediation/{control_id}/approve")
async def approve_remediation(
    control_id: str, body: RemediationApproveRequest, user=Depends(require_operator)
):
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        # X-User-Role lets Remediation's approval matrix (docs/Additional-
        # Features.md §7) tell a Network Operator from a Security Lead —
        # require_operator above only gates "some approver role", not which one.
        headers = {"X-User-Id": user["sub"], "X-User-Role": user.get("role", "")}
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


@app.post("/api/remediation/{control_id}/apply")
async def apply_remediation(control_id: str, body: RemediationAuditRunScopedRequest, user=Depends(require_operator)):
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        resp = await client.post(
            f"{REMEDIATION_URL}/remediation/{control_id}/apply",
            json=body.model_dump(), headers={"X-User-Id": user["sub"]},
        )
    if resp.status_code >= 400:
        raise upstream_error(resp)
    return resp.json()


@app.post("/api/remediation/{control_id}/rollback")
async def rollback_remediation(control_id: str, body: RemediationRollbackRequest, user=Depends(require_operator)):
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        resp = await client.post(
            f"{REMEDIATION_URL}/remediation/{control_id}/rollback",
            json=body.model_dump(), headers={"X-User-Id": user["sub"]},
        )
    if resp.status_code >= 400:
        raise upstream_error(resp)
    return resp.json()


@app.get("/api/fleet-score")
async def fleet_score(user=Depends(require_reader)):
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        resp = await client.get(f"{COMPLIANCE_URL}/fleet-score")
    if resp.status_code >= 400:
        raise upstream_error(resp)
    return resp.json()


@app.get("/api/mttr")
async def mttr(user=Depends(require_reader)):
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        resp = await client.get(f"{REPORTING_URL}/mttr")
    if resp.status_code >= 400:
        raise upstream_error(resp)
    return resp.json()


@app.post("/api/reachability-diff")
async def reachability_diff(body: ReachabilityDiffRequest, user=Depends(require_reader)):
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        resp = await client.post(f"{COMPLIANCE_URL}/reachability-diff", json=body.model_dump())
    if resp.status_code >= 400:
        raise upstream_error(resp)
    return resp.json()


@app.post("/api/counterfactual")
async def counterfactual(body: CounterfactualRequest, user=Depends(require_reader)):
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        resp = await client.post(f"{COMPLIANCE_URL}/counterfactual", json=body.model_dump())
    if resp.status_code >= 400:
        raise upstream_error(resp)
    return resp.json()


@app.get("/api/executive-report")
async def executive_report(user=Depends(require_reader)):
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        resp = await client.get(f"{REPORTING_URL}/executive-report")
    if resp.status_code >= 400:
        raise upstream_error(resp)
    return resp.json()


@app.get("/api/provenance/{run_id}/{control_id}")
async def provenance(run_id: str, control_id: str, user=Depends(require_reader)):
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        resp = await client.get(f"{REPORTING_URL}/provenance/{run_id}/{control_id}")
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
