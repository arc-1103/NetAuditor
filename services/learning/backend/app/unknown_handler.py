"""
Celery consumer for the Parsing -> Learning hop (unrecognized config blocks).

Run: python -m app.unknown_handler

Task name: `learning.receive_unknown_block`
Payload (Parsing lane sends this when a chunk fails Pydantic validation):

    {
      "block_id":      "<audit_run_id>:<chunk_index>",
      "audit_run_id":  "<uuid — the job_id Ingestion generated>",
      "raw_text":      "<the unparsed config chunk>",
      "chunk_context": { "vendor": ..., "os": ..., ... }   # optional
    }

Parsing does not have to wait for this lane to be up — Celery queues the task.
"""

import asyncio
import os

from celery import Celery

from app import db

celery_app = Celery("learning", broker=os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0"))


@celery_app.task(name="learning.receive_unknown_block")
def receive_unknown_block(block: dict) -> dict:
    """Queue a config chunk that failed schema validation upstream for a
    human to map.

    Raises on a malformed payload rather than dropping it silently: a block
    with no audit_run_id can never be traced back to the device it came
    from, and one with no block_id can't be deduplicated on resubmission.
    """
    block_id = block.get("block_id")
    if not block_id:
        raise ValueError("learning.receive_unknown_block requires 'block_id'")

    audit_run_id = block.get("audit_run_id")
    if not audit_run_id:
        raise ValueError("learning.receive_unknown_block requires 'audit_run_id'")

    raw_text = block.get("raw_text")
    if not isinstance(raw_text, str):
        raise ValueError("learning.receive_unknown_block requires 'raw_text' as a string")

    asyncio.run(db.enqueue_block(block_id, audit_run_id, raw_text, block.get("chunk_context")))
    return {"queued": True, "block_id": block_id}


if __name__ == "__main__":
    celery_app.worker_main(["worker", "--loglevel=info", "--concurrency=2", "-Q", "learning"])
