import json
import os
from datetime import datetime, timezone

from sqlalchemy import bindparam, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

POSTGRES_DSN = os.getenv(
    "POSTGRES_DSN",
    "postgresql+asyncpg://netaudit:changeme_in_local_env@postgres:5432/netaudit",
)
engine = create_async_engine(POSTGRES_DSN, echo=False)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_report_data(audit_run_id: str) -> dict | None:
    async with async_session() as session:
        run = (await session.execute(text("""
            SELECT id, file_hash, original_filename, status, detected_vendor,
                   detected_os, parsing_confidence, schema_version,
                   created_at, updated_at
            FROM audit_runs WHERE id=:run_id
        """), {"run_id": audit_run_id})).mappings().first()
        if run is None:
            return None
        findings = (await session.execute(text("""
            SELECT control_id, framework, title, status, severity, evidence,
                   remediation, risk_score, blast_radius, source_lines, created_at
            FROM compliance_findings WHERE audit_run_id=:run_id
            ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                     WHEN 'MEDIUM' THEN 3 ELSE 4 END, control_id
        """), {"run_id": audit_run_id})).mappings().all()
        remediations = (await session.execute(text("""
            SELECT control_id, script, rollback_script, source, preflight_status, risk_flags,
                   approval_status, approval_comment, approved_at
            FROM remediation_proposals WHERE audit_run_id=:run_id
            ORDER BY control_id
        """), {"run_id": audit_run_id})).mappings().all()
        evaluation = (await session.execute(text("""
            SELECT framework, policy_bundle_version, schema_version,
                   baseline_sha256, evaluated_at
            FROM audit_evaluations WHERE audit_run_id=:run_id
            ORDER BY evaluated_at DESC LIMIT 1
        """), {"run_id": audit_run_id})).mappings().first()
    result = {**_jsonable(run), "findings": [_jsonable(r) for r in findings],
              "remediations": [_jsonable(r) for r in remediations],
              "evaluation": _jsonable(evaluation) if evaluation else None}
    for item in result["findings"]:
        if isinstance(item.get("blast_radius"), str):
            item["blast_radius"] = json.loads(item["blast_radius"])
        if isinstance(item.get("source_lines"), str):
            item["source_lines"] = json.loads(item["source_lines"])
    for item in result["remediations"]:
        if isinstance(item.get("risk_flags"), str):
            item["risk_flags"] = json.loads(item["risk_flags"])
    return result


async def get_fleet_report_inputs() -> dict:
    """Everything app/executive_report.py's functions need for docs/
    Additional-Features.md §6, fetched in one pass: current findings and
    run metadata for every EVALUATED/COMPLETE run, the full audit_evaluations
    history for the trend line, every remediation proposal, and the ledger's
    VIOLATION_DETECTED events."""
    async with async_session() as session:
        runs = (await session.execute(text(
            "SELECT id, original_filename, detected_vendor, detected_os "
            "FROM audit_runs WHERE status IN ('EVALUATED', 'COMPLETE')"
        ))).mappings().all()
        run_ids = [r["id"] for r in runs]
        findings_by_run: dict[str, list[dict]] = {str(r["id"]): [] for r in runs}
        if run_ids:
            finding_rows = (await session.execute(
                text("SELECT audit_run_id, control_id, severity, risk_score FROM compliance_findings WHERE audit_run_id IN :run_ids")
                .bindparams(bindparam("run_ids", expanding=True)),
                {"run_ids": run_ids},
            )).mappings().all()
            for row in finding_rows:
                findings_by_run[str(row["audit_run_id"])].append(dict(row))

        evaluations = (await session.execute(text(
            "SELECT audit_run_id, evaluated_at, findings_snapshot FROM audit_evaluations ORDER BY evaluated_at"
        ))).mappings().all()
        evaluations = [dict(e) for e in evaluations]
        for e in evaluations:
            e["audit_run_id"] = str(e["audit_run_id"])
            if isinstance(e["findings_snapshot"], str):
                e["findings_snapshot"] = json.loads(e["findings_snapshot"])

        proposals = (await session.execute(text(
            "SELECT audit_run_id, control_id, approval_status, decision_action, "
            "preflight_status, applied_at FROM remediation_proposals"
        ))).mappings().all()

    run_metadata = {
        str(r["id"]): {
            "original_filename": r["original_filename"],
            "detected_vendor": r["detected_vendor"],
            "detected_os": r["detected_os"],
        }
        for r in runs
    }
    violation_events = await get_ledger_events(("VIOLATION_DETECTED",))
    return {
        "findings_by_run": findings_by_run,
        "run_metadata": run_metadata,
        "evaluations": evaluations,
        "proposals": [dict(p) for p in proposals],
        "violation_events": violation_events,
    }


async def get_ledger_events(event_types: tuple[str, ...]) -> list[dict]:
    """Raw ledger_events rows for app/mttr.py — created_at stays a datetime
    (not stringified) so durations can be computed directly, and payload is
    decoded from its JSON text now rather than by each caller."""
    async with async_session() as session:
        rows = (await session.execute(
            text("SELECT audit_run_id, control_id, event_type, actor, ruleset_version, payload, created_at "
                 "FROM ledger_events WHERE event_type IN :event_types")
            .bindparams(bindparam("event_types", expanding=True)),
            {"event_types": list(event_types)},
        )).mappings().all()
    events = [dict(r) for r in rows]
    for event in events:
        if isinstance(event.get("payload"), str):
            event["payload"] = json.loads(event["payload"])
    return events


async def get_provenance_chain(audit_run_id: str, control_id: str) -> dict:
    """docs/Additional-Features.md §6 / docs/Suggestions.md item 5: "full
    provenance chain for any single finding, linked by ID" — every field
    item 5 names (framework control, policy version, evidence/raw config
    line, config hash, remediation, preflight result, who approved),
    composed from the four tables that each already own one piece of it,
    plus the ledger's own event-by-event trail. Nothing new is computed
    here; this is a join, not a new source of truth."""
    async with async_session() as session:
        finding = (await session.execute(text(
            "SELECT control_id, framework, title, status, severity, evidence, remediation, "
            "risk_score, blast_radius, source_lines FROM compliance_findings "
            "WHERE audit_run_id=:run_id AND control_id=:control_id"
        ), {"run_id": audit_run_id, "control_id": control_id})).mappings().first()
        evaluation = (await session.execute(text(
            "SELECT framework, policy_bundle_version, schema_version, baseline_sha256, evaluated_at "
            "FROM audit_evaluations WHERE audit_run_id=:run_id ORDER BY evaluated_at DESC LIMIT 1"
        ), {"run_id": audit_run_id})).mappings().first()
        proposal = (await session.execute(text(
            "SELECT template_name, script, source, preflight_status, risk_flags, decision_action, "
            "decision_ruleset_version, risk_tier, blast_radius_count, approval_status, approved_by, "
            "approval_comment, approved_at, rollback_status FROM remediation_proposals "
            "WHERE audit_run_id=:run_id AND control_id=:control_id"
        ), {"run_id": audit_run_id, "control_id": control_id})).mappings().first()
        events = (await session.execute(text(
            "SELECT event_type, actor, ruleset_version, payload, created_at FROM ledger_events "
            "WHERE audit_run_id=:run_id AND control_id=:control_id ORDER BY created_at"
        ), {"run_id": audit_run_id, "control_id": control_id})).mappings().all()

    events = [_jsonable(r) for r in events]
    for event in events:
        if isinstance(event.get("payload"), str):
            event["payload"] = json.loads(event["payload"])

    result = {
        "audit_run_id": audit_run_id,
        "control_id": control_id,
        "finding": _jsonable(finding) if finding else None,
        "policy": _jsonable(evaluation) if evaluation else None,
        "remediation": _jsonable(proposal) if proposal else None,
        "events": events,
    }
    if result["finding"]:
        for field in ("blast_radius", "source_lines"):
            if isinstance(result["finding"].get(field), str):
                result["finding"][field] = json.loads(result["finding"][field])
    if result["remediation"] and isinstance(result["remediation"].get("risk_flags"), str):
        result["remediation"]["risk_flags"] = json.loads(result["remediation"]["risk_flags"])
    return result


async def record_report(audit_run_id: str, path: str, generated_by: str) -> None:
    now = datetime.now(timezone.utc)
    async with async_session() as session, session.begin():
        await session.execute(text("""
            INSERT INTO generated_reports (audit_run_id, file_path, generated_by, generated_at)
            VALUES (:run_id, :path, :user_id, :now)
        """), {"run_id": audit_run_id, "path": path, "user_id": generated_by, "now": now})
        await session.execute(text("""
            UPDATE audit_runs SET status='COMPLETE', updated_at=:now WHERE id=:run_id
        """), {"run_id": audit_run_id, "now": now})
        await session.execute(text("""
            INSERT INTO ledger_events (audit_run_id, control_id, event_type, actor, payload)
            VALUES (:run_id, NULL, 'REPORT_GENERATED', :user_id, :payload)
        """), {"run_id": audit_run_id, "user_id": generated_by or "unknown", "payload": json.dumps({"file_path": path})})


def _jsonable(row) -> dict:
    return json.loads(json.dumps(dict(row), default=str))
