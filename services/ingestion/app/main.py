"""
Ingestion service entrypoint.
Run: uvicorn app.main:app --reload --port 8001
"""
import uuid
from fastapi import FastAPI, UploadFile, File, Header, HTTPException
from app.uploader import validate_and_store, DuplicateFileError
from app.chunker import chunk_config
from app.queue_producer import enqueue_parsing_job
from app.db import create_audit_run, get_audit_run_id_by_hash

app = FastAPI(title="netaudit-ingestion")

@app.get("/health")
async def health():
    return {"status": "ok", "service": "ingestion"}

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
    try:
        stored = await validate_and_store(file)
    except DuplicateFileError as e:
        # Same bytes already ingested — reopen that audit run rather than
        # dead-ending the upload. The response shape matches a fresh
        # upload's, so callers (frontend's uploadConfig -> getAudit) need no
        # special-casing.
        existing_run_id = await get_audit_run_id_by_hash(e.file_hash)
        if existing_run_id:
            return {"job_id": existing_run_id, "status": "already_processed"}
        raise HTTPException(status_code=400, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Gateway forwards the JWT subject as X-User-Id; this hop itself is
    # unauthenticated (internal network), so a missing/malformed header
    # (e.g. a direct service-to-service call) degrades to no attribution
    # rather than failing the upload.
    try:
        uploaded_by = str(uuid.UUID(x_user_id)) if x_user_id else None
    except ValueError:
        uploaded_by = None

    run_id = str(uuid.uuid4())
    await create_audit_run(run_id, stored, uploaded_by)

    chunks = chunk_config(stored["raw_text"])
    job = enqueue_parsing_job(run_id, stored, chunks, uploaded_by)
    return {"job_id": job["job_id"], "status": "queued"}
