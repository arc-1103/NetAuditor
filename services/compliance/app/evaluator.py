"""
The one compliance pass: OPA evaluate -> risk score -> persist.

Lives on its own because both entry points run it — app/worker.py for the
async Celery path from Parsing, and app/main.py for the synchronous
POST /evaluate used in demos and integration tests.
"""

from app import db, opa_client, risk_scorer


async def evaluate_baseline(baseline: dict, framework: str | None = None, audit_run_id: str | None = None) -> dict:
    """Evaluate one normalized baseline and return findings + summary.

    Persists only when `audit_run_id` is given — a caller checking a config
    without an AuditRun row (the standalone demo path) would otherwise trip
    the compliance_findings foreign key.
    """
    findings = risk_scorer.score_findings(await opa_client.evaluate(baseline, framework))
    summary = risk_scorer.summarize(findings)

    if audit_run_id:
        await db.save_findings(audit_run_id, findings)

    return {
        "audit_run_id": audit_run_id,
        "framework": (framework or opa_client.DEFAULT_FRAMEWORK).upper(),
        "device": baseline.get("device", {}),
        "findings": findings,
        "summary": summary,
    }
