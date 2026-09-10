import json
import os
from datetime import datetime, timezone

from sqlalchemy import text
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


def _jsonable(row) -> dict:
    return json.loads(json.dumps(dict(row), default=str))
