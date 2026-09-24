"""
Pushes a parsing job to Celery/Redis. Payload MUST match
/contracts/ingestion_job.schema.json — do not add/remove fields here
without updating that file and telling the Parsing lane.
"""
import os
from datetime import datetime, timezone
from celery import Celery

celery_app = Celery("ingestion", broker=os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0"))


def enqueue_parsing_job(job_id: str, stored: dict, chunks: list[str], uploaded_by: str | None) -> dict:
    job = {
        "job_id": job_id,
        "file_hash": stored["file_hash"],
        "storage_path": stored["storage_path"],
        "original_filename": stored.get("original_filename"),
        "uploaded_by": uploaded_by or "unknown",
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
        "chunk_count": len(chunks),
        "chunks": [{"index": i, "text": c} for i, c in enumerate(chunks)],
    }
    celery_app.send_task("parsing.process_config", args=[job], queue="parsing")
    return job
