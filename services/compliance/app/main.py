"""
Compliance service entrypoint.
Run: uvicorn app.main:app --reload --port 8002

Serves the read side of this lane. The Gateway proxies
GET /api/audit-runs/{id} here (contracts/api_gateway_routes.md); the write
side normally arrives as a Celery task — see app/worker.py.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from app import db
from app.evaluator import evaluate_baseline
from app.opa_client import OPAEvaluationError
from app.risk_scorer import summarize

app = FastAPI(title="netaudit-compliance")


class EvaluateRequest(BaseModel):
    # contracts/security_baseline.schema.json — kept as an open dict rather
    # than re-declaring the model here; services/schema/ is its home and
    # duplicating it in this lane would be a second source of truth.
    baseline: dict
    framework: str | None = None
    audit_run_id: str | None = None


@app.get("/health")
async def health():
    return {"status": "ok", "service": "compliance"}


@app.post("/evaluate")
async def evaluate(body: EvaluateRequest):
    """Evaluate a baseline now, instead of waiting for a Celery job.

    Findings are persisted only when audit_run_id is supplied, so this doubles
    as a dry-run against a config that was never uploaded.
    """
    try:
        return await evaluate_baseline(body.baseline, body.framework, body.audit_run_id)
    except ValueError as e:  # unknown framework
        raise HTTPException(status_code=400, detail=str(e))
    except OPAEvaluationError as e:
        # 502, not 500: the policy engine is a dependency of this service, and
        # the caller needs to know the verdict is missing, not that it's clean.
        raise HTTPException(status_code=502, detail=str(e))


@app.get("/audit-runs/{run_id}")
async def get_audit_run(run_id: str):
    run = await db.get_audit_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"No audit run {run_id}")
    return {**run, "summary": summarize(run["findings"])}
