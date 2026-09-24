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
from app.evaluator import evaluate_baseline, shutdown_graph_provider
from app.opa_client import OPAEvaluationError
from app.risk_scorer import summarize

app = FastAPI(title="netaudit-compliance")

# A run only has trustworthy findings once it's actually been evaluated —
# for any other status (INGESTED, NEEDS_REVIEW, ...) findings is empty
# because evaluation never ran, not because the device is clean.
# summarize([]) would otherwise report a fabricated 100/100 for a
# never-audited run. compliance_score/control_pass_rate are None here so
# the frontend can tell "not scored" apart from "scored 0" or "scored 100".
_NOT_EVALUATED_SUMMARY = {
    "total_findings": 0,
    "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
    "risk_score": 0,
    "compliance_score": None,
    "controls_evaluated": 0,
    "controls_failed": 0,
    "controls_passed": 0,
    "control_pass_rate": None,
}


@app.on_event("shutdown")
async def _close_graph_provider() -> None:
    """The topology graph driver (app/evaluator.py) is built once and reused
    for the app's lifetime; close it at process exit rather than leaking the
    connection."""
    await shutdown_graph_provider()


class EvaluateRequest(BaseModel):
    # contracts/security_baseline.schema.json — kept as an open dict rather
    # than re-declaring the model here; services/schema/ is its home and
    # duplicating it in this lane would be a second source of truth.
    baseline: dict
    framework: str | None = None
    audit_run_id: str | None = None
    source_text: str | None = None


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
        return await evaluate_baseline(
            body.baseline, body.framework, body.audit_run_id, source_text=body.source_text
        )
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
    summary = summarize(run["findings"]) if run["status"] in {"EVALUATED", "COMPLETE"} else _NOT_EVALUATED_SUMMARY
    return {**run, "summary": summary}
