"""
Compliance service entrypoint.
Run: uvicorn app.main:app --reload --port 8002

Serves the read side of this lane. The Gateway proxies
GET /api/audit-runs/{id} here (contracts/api_gateway_routes.md); the write
side normally arrives as a Celery task — see app/worker.py.
"""

import asyncio
import uuid
from datetime import datetime, timezone

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from app import db, evaluator, ledger_seal, ledger_service, opa_client
from app.counterfactual import counterfactual
from app.evaluator import evaluate_baseline, shutdown_graph_provider
from app import waivers as waiver_logic
from app.risk_map import build_risk_map
from app.drift import baseline_diff, build_history
from app.fix_simulation import apply_fix
from app.opa_client import OPAEvaluationError
from app.reachability_diff import diff_acl
from app.risk_scorer import control_results, fleet_score, summarize
from app.trust import build_trust_view

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


@app.on_event("startup")
async def _start_ledger_sealer() -> None:
    if ledger_service.SEAL_INTERVAL_SECONDS > 0 and ledger_seal.load_signing_key() is not None:
        asyncio.create_task(ledger_service.seal_forever())


@app.on_event("shutdown")
async def _close_graph_provider() -> None:
    """The topology graph driver (app/evaluator.py) is built once and reused
    for the app's lifetime; close it at process exit rather than leaking the
    connection."""
    await shutdown_graph_provider()


class CounterfactualRequest(BaseModel):
    # SecurityBaseline-shaped dicts, same reasoning as EvaluateRequest.baseline.
    current_baseline: dict
    proposed_baseline: dict
    framework: str | None = None


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
    parser_agreement: float | None = None


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
            body.baseline, body.framework, body.audit_run_id,
            source_text=body.source_text, parser_agreement=body.parser_agreement,
        )
    except ValueError as e:  # unknown framework
        raise HTTPException(status_code=400, detail=str(e))
    except OPAEvaluationError as e:
        # 502, not 500: the policy engine is a dependency of this service, and
        # the caller needs to know the verdict is missing, not that it's clean.
        raise HTTPException(status_code=502, detail=str(e))


@app.get("/audit-runs")
async def list_audit_runs(limit: int = 20):
    return {"run_ids": await db.list_evaluated_run_ids(max(1, min(limit, 50)))}


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
    # Waived findings stay in `findings` (annotated); they just stop counting
    # against the score, which is also reported without waivers.
    listing = waiver_logic.evaluate(await db.get_waiver_events(), datetime.now(timezone.utc))
    findings = waiver_logic.annotate(run["findings"], listing, run["device_key"])
    counting, waived = waiver_logic.split(findings)
    if is_evaluated:
        summary = {**summarize(counting), "waived": len(waived), "score_without_waivers": summarize(run["findings"])["compliance_score"]}
    else:
        summary = _NOT_EVALUATED_SUMMARY
    results = control_results(findings) if is_evaluated else []
    return {**run, "findings": findings, "summary": summary, "control_results": results}


@app.post("/counterfactual")
async def counterfactual_endpoint(body: CounterfactualRequest):
    """docs/Suggestions.md item 3 — "what happens if I apply this fix?"
    Scores both baselines through the same OPA bundle a real upload uses,
    without persisting either or touching GraphRAG/anomaly enrichment (see
    app/counterfactual.py for why), then diffs the result."""
    try:
        current_findings = await opa_client.evaluate(body.current_baseline, body.framework)
        proposed_findings = await opa_client.evaluate(body.proposed_baseline, body.framework)
    except ValueError as e:  # unknown framework
        raise HTTPException(status_code=400, detail=str(e))
    except OPAEvaluationError as e:
        raise HTTPException(status_code=502, detail=str(e))
    return counterfactual(
        current_findings, proposed_findings,
        body.current_baseline.get("acl"), body.proposed_baseline.get("acl"),
        body.current_baseline.get("topology"), body.proposed_baseline.get("topology"),
    )


@app.get("/audit-runs/{run_id}/trust")
async def get_trust_view(run_id: str):
    """docs/Suggestions.md item 7 (AI Interpretation Trust Layer) — per-field
    SLM-vs-TextFSM agreement. See app/trust.py."""
    data = await db.get_trust_data(run_id)
    if data is None:
        raise HTTPException(status_code=404, detail=f"No audit run {run_id}")
    return build_trust_view(data["baseline_snapshot"], data["deterministic_baseline"], data["parser_agreement"])


@app.get("/audit-runs/{run_id}/counterfactual/{control_id}")
async def simulate_fix(run_id: str, control_id: str):
    """docs/Suggestions.md item 3 for one finding: the run's stored baseline
    vs the same baseline with `control_id` fixed (app/fix_simulation.py),
    scored through the normal OPA path and diffed by app/counterfactual.py."""
    data = await db.get_trust_data(run_id)
    if data is None or not data["baseline_snapshot"]:
        raise HTTPException(status_code=404, detail=f"No evaluated baseline for audit run {run_id}")
    current = data["baseline_snapshot"]
    proposed = apply_fix(current, control_id)
    if proposed is None:
        raise HTTPException(status_code=422, detail=f"No fix simulation is defined for {control_id}")
    try:
        current_findings = await opa_client.evaluate(current)
        proposed_findings = await opa_client.evaluate(proposed)
    except OPAEvaluationError as e:
        raise HTTPException(status_code=502, detail=str(e))
    result = counterfactual(
        current_findings, proposed_findings,
        current.get("acl"), proposed.get("acl"), current.get("topology"), proposed.get("topology"),
    )
    return {"control_id": control_id, "simulated": True, **result}


@app.get("/audit-runs/{run_id}/history")
async def get_history(run_id: str):
    """Sequential audits of this device up to this run: what changed between
    each pair, and since when each currently failing control has been failing."""
    runs = await db.get_device_runs(run_id)
    history = build_history(runs, run_id)
    if not history["runs"]:
        raise HTTPException(status_code=404, detail=f"No audit run {run_id}")
    return history


@app.get("/audit-runs/{run_id}/drift/{control_id}")
async def drift_since_last_pass(run_id: str, control_id: str):
    """The 'time machine' for one failing control: diff this audit's baseline
    against the most recent earlier audit of the same device where the control
    passed, and return the configuration lines that evidence the failure now."""
    history = build_history(await db.get_device_runs(run_id), run_id)
    streak = history["control_streaks"].get(control_id)
    if streak is None:
        raise HTTPException(status_code=404, detail=f"{control_id} is not failing in audit {run_id}")
    baseline_run = streak["last_passed_run"]
    if baseline_run is None:
        return {"control_id": control_id, "compared_to": None, "changes": [], "evidence": None,
                "note": "This is the device's first audit, so there is no earlier state to compare with."}
    earlier = await db.get_trust_data(baseline_run)
    current = await db.get_trust_data(run_id)
    run = await db.get_audit_run(run_id)
    finding = next((f for f in (run or {}).get("findings", []) if f["control_id"] == control_id), None)
    compared = next(r for r in history["runs"] if r["run_id"] == baseline_run)
    return {
        "control_id": control_id,
        "compared_to": {"run_id": baseline_run, "created_at": compared["created_at"], "filename": compared["filename"]},
        "changes": baseline_diff((earlier or {}).get("baseline_snapshot"), (current or {}).get("baseline_snapshot"), control_id),
        "evidence": {"text": finding["evidence"], "source_lines": finding["source_lines"]} if finding else None,
    }


def _ledger_unavailable(exc: ledger_seal.LedgerSealError) -> HTTPException:
    return HTTPException(status_code=503, detail=str(exc))


@app.get("/ledger/status")
async def ledger_status():
    return await ledger_service.status()


@app.post("/ledger/seal")
async def ledger_seal_now():
    """Seal every not-yet-sealed ledger event into a signed Merkle root (app/ledger_seal.py)."""
    try:
        return await ledger_service.seal_now()
    except ledger_seal.LedgerSealError as exc:
        raise _ledger_unavailable(exc)


@app.get("/ledger/verify")
async def ledger_verify():
    """Recompute every seal from the stored events and report any tampering."""
    try:
        return await ledger_service.verify()
    except ledger_seal.LedgerSealError as exc:
        raise _ledger_unavailable(exc)


@app.get("/ledger/proof/{event_id}")
async def ledger_proof(event_id: str):
    try:
        return await ledger_service.proof(event_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"No ledger event {event_id}")
    except ledger_seal.LedgerSealError as exc:
        raise _ledger_unavailable(exc)


@app.get("/topology/fleet")
async def fleet_topology():
    """Every known routing adjacency with each device's audit result overlaid,
    plus the path from the weakest device to the core (app/risk_map.py). Empty
    (not an error) when Neo4j is off — the same optional-enrichment contract as
    the per-device topology."""
    try:
        graph = await evaluator._get_graph_provider().fleet_topology(limit=200)
    except Exception:
        graph = {"nodes": [], "edges": []}
    return build_risk_map(graph, await db.get_device_risk_by_hash())


class WaiverRequest(BaseModel):
    audit_run_id: str
    control_id: str
    reason: str
    expires_at: str
    ticket: str | None = None


class RevokeRequest(BaseModel):
    reason: str = ""


def _actor(x_user_email: str | None, x_user_id: str | None) -> str:
    return x_user_email or x_user_id or "unknown"


@app.get("/waivers")
async def list_waivers(status: str | None = None):
    listing = waiver_logic.evaluate(await db.get_waiver_events(), datetime.now(timezone.utc))
    return {"waivers": [w for w in listing if status is None or w["status"] == status.upper()]}


@app.post("/waivers")
async def grant_waiver(body: WaiverRequest, x_user_email: str | None = Header(default=None), x_user_id: str | None = Header(default=None)):
    """Accept the risk of one failing control on one device until a date. The
    finding is not hidden; the grant is an append-only ledger event, sealed when a
    signing key is configured (app/waivers.py)."""
    now = datetime.now(timezone.utc)
    run = await db.get_audit_run(body.audit_run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"No audit run {body.audit_run_id}")
    if body.control_id not in {f["control_id"] for f in run["findings"]}:
        raise HTTPException(status_code=422, detail=f"{body.control_id} is not failing in this audit, so there is nothing to waive")
    try:
        expiry = waiver_logic.validate_grant(body.reason, body.expires_at, now)
    except waiver_logic.WaiverError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    waiver_id = str(uuid.uuid4())
    await db.insert_waiver_event(waiver_id, body.audit_run_id, body.control_id, waiver_logic.GRANTED, _actor(x_user_email, x_user_id), {
        "waiver_id": waiver_id, "device_key": run["device_key"], "reason": body.reason.strip(),
        "expires_at": expiry.isoformat(), "ticket": body.ticket,
    })
    await _seal_quietly()
    listing = waiver_logic.evaluate(await db.get_waiver_events(), now)
    return next(w for w in listing if w["waiver_id"] == waiver_id)


@app.post("/waivers/{waiver_id}/revoke")
async def revoke_waiver(waiver_id: str, body: RevokeRequest, x_user_email: str | None = Header(default=None), x_user_id: str | None = Header(default=None)):
    listing = waiver_logic.evaluate(await db.get_waiver_events(), datetime.now(timezone.utc))
    waiver = next((w for w in listing if w["waiver_id"] == waiver_id), None)
    if waiver is None:
        raise HTTPException(status_code=404, detail=f"No waiver {waiver_id}")
    if waiver["status"] != "ACTIVE":
        raise HTTPException(status_code=409, detail=f"This waiver is already {waiver['status'].lower()}")
    await db.insert_waiver_event(str(uuid.uuid4()), waiver["audit_run_id"], waiver["control_id"], waiver_logic.REVOKED,
                                 _actor(x_user_email, x_user_id), {"waiver_id": waiver_id, "reason": body.reason.strip()})
    await _seal_quietly()
    return next(w for w in waiver_logic.evaluate(await db.get_waiver_events(), datetime.now(timezone.utc)) if w["waiver_id"] == waiver_id)


async def _seal_quietly() -> None:
    """Commit the new ledger event to a signed seal straight away when a signing
    key exists. Sealing is an integrity upgrade, not a precondition."""
    try:
        await ledger_service.seal_now()
    except Exception:
        pass


@app.get("/audit-runs/{run_id}/topology")
async def get_topology(run_id: str):
    """The routing neighborhood behind this run's blast_radius, as nodes and
    edges for the UI graph. Empty (not an error) when Neo4j is off — the same
    optional-enrichment contract as blast_radius itself."""
    data = await db.get_trust_data(run_id)
    if data is None:
        raise HTTPException(status_code=404, detail=f"No audit run {run_id}")
    device_id = ((data["baseline_snapshot"] or {}).get("device") or {}).get("config_sha256")
    if not device_id:
        return {"center": None, "nodes": [], "edges": []}
    try:
        graph = await evaluator._get_graph_provider().topology(device_id, max_hops=evaluator.GRAPH_BLAST_RADIUS_MAX_HOPS)
    except Exception:
        return {"center": device_id, "nodes": [], "edges": []}
    return {"center": device_id, **graph}


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
