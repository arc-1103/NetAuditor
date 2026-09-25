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
from app.reachability_diff import diff_acl
from app.risk_scorer import fleet_score, summarize

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


class ReachabilityDiffRequest(BaseModel):
    # ACLConfig-shaped dicts — kept as open dicts for the same reason
    # EvaluateRequest.baseline is: services/schema/ is the shape's home, and
    # re-declaring it here would be a second source of truth.
    before: dict
    after: dict


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
    # An empty findings list means "0 violations" only once evaluation has
    # actually happened. Before that (INGESTED, NEEDS_REVIEW), summarize([])
    # would read as a device that passed every check — summarize() has no
    # way to tell "clean" from "never evaluated" apart, so gate on status
    # here instead of inside it. COMPLETE (report generated) still has real,
    # trustworthy findings from its earlier evaluation — only EVALUATED and
    # COMPLETE runs get a real summary.
    is_evaluated = run["status"] in {db.STATUS_EVALUATED, "COMPLETE"}
    summary = summarize(run["findings"]) if is_evaluated else _NOT_EVALUATED_SUMMARY
    return {**run, "summary": summary}


@app.post("/reachability-diff")
async def reachability_diff(body: ReachabilityDiffRequest):
    """docs/Additional-Features.md §4 — deterministic ACL diff fallback,
    for when a caller needs an approximate blast radius without a full
    Batfish topology simulation. See app/reachability_diff.py."""
    return diff_acl(body.before, body.after)


@app.get("/fleet-score")
async def get_fleet_score():
    """docs/Additional-Features.md §1's fleet-wide rollup — weighted by
    total control weight across every evaluated run, not an average of each
    run's own compliance_score. See app.risk_scorer.fleet_score."""
    return fleet_score(await db.get_findings_by_run())
