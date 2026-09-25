"""
Celery consumer for the Parsing -> Compliance hop.

Run: python -m app.worker

Task name: `compliance.evaluate_baseline`
Payload (Parsing lane sends this once a baseline passes Pydantic validation):

    {
      "audit_run_id": "<uuid — the job_id Ingestion generated>",
      "framework":    "CIS",            # optional, defaults to DEFAULT_FRAMEWORK
      "baseline":     { ... },          # contracts/security_baseline.schema.json
      "source_text":  "..."             # optional sanitized evidence
      "parser_agreement": 0.0-1.0|null  # optional, see app/agreement.py in Parsing
      "deterministic_baseline": { ... } # optional partial baseline, see app/deterministic_extractor.py in Parsing
    }

Parsing does not have to wait for this lane to be up — Celery queues the task.
"""

import asyncio
import os

from celery import Celery

from app.evaluator import evaluate_baseline as run_evaluation

celery_app = Celery("compliance", broker=os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0"))

# One event loop for the worker process's lifetime, not one per task: the
# async engine's asyncpg connections are bound to whichever loop opened them,
# so asyncio.run() (new loop + close every call) breaks the pool on the
# second task in a process.
_loop = asyncio.new_event_loop()


def _run(coro):
    return _loop.run_until_complete(coro)


@celery_app.task(name="compliance.evaluate_baseline")
def evaluate_baseline(job: dict) -> dict:
    """Evaluate a parsed baseline and persist its findings.

    Raises on a malformed payload rather than defaulting: a job with no
    audit_run_id would evaluate into the void, and one with no baseline would
    report a device with zero findings as fully compliant.
    """
    audit_run_id = job.get("audit_run_id")
    if not audit_run_id:
        raise ValueError("compliance.evaluate_baseline requires 'audit_run_id'")

    baseline = job.get("baseline")
    if not isinstance(baseline, dict):
        raise ValueError("compliance.evaluate_baseline requires 'baseline' as an object")

    result = _run(
        run_evaluation(
            baseline,
            job.get("framework"),
            audit_run_id,
            source_text=job.get("source_text"),
            parser_agreement=job.get("parser_agreement"),
            deterministic_baseline=job.get("deterministic_baseline"),
        )
    )
    return result["summary"]


if __name__ == "__main__":
    celery_app.worker_main(["worker", "--loglevel=info", "--concurrency=4", "-Q", "compliance"])
