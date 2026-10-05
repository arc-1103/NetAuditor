"""
Ingestion service entrypoint.
Run: uvicorn app.main:app --reload --port 8001
"""
import uuid
from fastapi import FastAPI, UploadFile, File, Header, HTTPException
from pydantic import BaseModel, Field, SecretStr
from app.collector import CollectorError, collect_config
from app.uploader import validate_and_store
from app.chunker import chunk_hierarchical
from app.queue_producer import enqueue_parsing_job
from app.db import create_audit_run, get_audit_run_id_by_hash

app = FastAPI(title="netaudit-ingestion")

@app.get("/health")
async def health():
    return {"status": "ok", "service": "ingestion"}

async def _ingest(file, x_user_id: str | None) -> dict:
    """Shared by /upload and /collect: validate, store, dedup, record, enqueue."""
    try:
        stored = await validate_and_store(file)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Postgres, not MinIO, is the dedup authority: validate_and_store always
    # (re)writes the content-addressed object, so a prior partial failure
    # (MinIO succeeded, this check never ran) leaves no audit_runs row and
    # self-heals here instead of permanently rejecting every retry. Same
    # bytes that WERE already fully ingested reopen that audit run rather
    # than dead-ending the upload — the response shape matches a fresh
    # upload's, so callers (frontend's uploadConfig -> getAudit) need no
    # special-casing.
    existing_run_id = await get_audit_run_id_by_hash(stored["file_hash"])
    if existing_run_id:
        return {"job_id": existing_run_id, "status": "already_processed"}

    # Gateway forwards the JWT subject as X-User-Id; this hop itself is
    # unauthenticated (internal network), so a missing/malformed header
    # (e.g. a direct service-to-service call) degrades to no attribution
    # rather than failing the upload.
    try:
        uploaded_by = str(uuid.UUID(x_user_id)) if x_user_id else None
    except ValueError:
        uploaded_by = None

    run_id = str(uuid.uuid4())
    if not await create_audit_run(run_id, stored, uploaded_by):
        # Lost a race with a concurrent upload of the same bytes (unique
        # index on file_hash): reopen the winner's run, don't enqueue twice.
        return {"job_id": await get_audit_run_id_by_hash(stored["file_hash"]), "status": "already_processed"}
    # `credential_evidence` (from validate_and_store) is already persisted
    # inside create_audit_run — see docs/ArchitecturalChanges.md §2.

    chunks = chunk_hierarchical(stored["raw_text"])
    job = enqueue_parsing_job(run_id, stored, chunks, uploaded_by)
    return {"job_id": job["job_id"], "status": "queued"}


@app.post("/upload")
async def upload_config(
    file: UploadFile = File(...),
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
):
    """
    Accepts a raw device config file, validates it, stores it in MinIO,
    records an AuditRun (status=INGESTED), and enqueues a parsing job.
    See /contracts/ingestion_job.schema.json for the exact payload shape
    sent to Parsing.
    """
    return await _ingest(file, x_user_id)


class CollectRequest(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    device_type: str
    username: str = Field(min_length=1, max_length=128)
    password: SecretStr
    port: int = 22
    method: str = "netmiko"


@app.post("/collect")
async def collect(body: CollectRequest, x_user_id: str | None = Header(default=None, alias="X-User-Id")):
    """
    Online ingest: log in to the device (Netmiko or NAPALM), read its running
    configuration, and feed it through the same pipeline as an upload. Disabled
    unless COLLECTOR_ENABLED=true and the host is inside COLLECTOR_ALLOWED_CIDRS
    (app/collector.py). Credentials are used once and never stored.
    """
    try:
        upload = await collect_config(
            body.host, body.port, body.device_type, body.username,
            body.password.get_secret_value(), body.method,
        )
    except CollectorError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return await _ingest(upload, x_user_id)
