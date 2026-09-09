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


async def save_proposal(proposal: dict) -> None:
    preflight = proposal["preflight"]
    async with async_session() as session, session.begin():
        await session.execute(
            text("""
                INSERT INTO remediation_proposals
                    (audit_run_id, control_id, template_name, script, rollback_script, source,
                     preflight_status, risk_flags, approval_status, updated_at)
                VALUES (:audit_run_id, :control_id, :template_name, :script, :rollback_script, :source,
                        :preflight_status, :risk_flags, 'PENDING', :updated_at)
                ON CONFLICT (audit_run_id, control_id) DO UPDATE SET
                    template_name = EXCLUDED.template_name,
                    script = EXCLUDED.script,
                    rollback_script = EXCLUDED.rollback_script,
                    source = EXCLUDED.source,
                    preflight_status = EXCLUDED.preflight_status,
                    risk_flags = EXCLUDED.risk_flags,
                    approval_status = 'PENDING', approved_by = NULL,
                    approval_comment = NULL, approved_at = NULL,
                    updated_at = EXCLUDED.updated_at
            """),
            {
                **{k: proposal[k] for k in ("audit_run_id", "control_id", "template_name", "script")},
                "rollback_script": proposal.get("rollback_script"),
                "source": proposal.get("source", "template"),
                "preflight_status": preflight["status"],
                "risk_flags": json.dumps(preflight.get("risk_flags", [])),
                "updated_at": datetime.now(timezone.utc),
            },
        )


async def approve(control_id: str, audit_run_id: str, approved: bool, user_id: str, comment: str | None) -> dict | None:
    status = "APPROVED" if approved else "REJECTED"
    now = datetime.now(timezone.utc)
    async with async_session() as session, session.begin():
        row = (await session.execute(
            text("""
                UPDATE remediation_proposals
                SET approval_status=:status, approved_by=:user_id,
                    approval_comment=:comment, approved_at=:now, updated_at=:now
                WHERE audit_run_id=:run_id AND control_id=:control_id
                  AND (:approved = false OR preflight_status = 'SAFE')
                RETURNING audit_run_id, control_id, template_name, script, rollback_script, source,
                          preflight_status, risk_flags, approval_status,
                          approved_by, approval_comment, approved_at
            """),
            {"status": status, "user_id": user_id, "comment": comment, "now": now,
             "run_id": audit_run_id, "control_id": control_id, "approved": approved},
        )).mappings().first()
    return _jsonable(row) if row else None


async def get_proposals(audit_run_id: str) -> list[dict]:
    async with async_session() as session:
        rows = (await session.execute(
            text("""
                SELECT audit_run_id, control_id, template_name, script, rollback_script, source,
                       preflight_status, risk_flags, approval_status,
                       approved_by, approval_comment, approved_at, updated_at
                FROM remediation_proposals WHERE audit_run_id=:run_id
                ORDER BY control_id
            """), {"run_id": audit_run_id}
        )).mappings().all()
    return [_jsonable(row) for row in rows]


async def get_findings(audit_run_id: str) -> list[dict]:
    async with async_session() as session:
        rows = (await session.execute(
            text("""
                SELECT control_id, framework, title, severity, evidence, remediation
                FROM compliance_findings
                WHERE audit_run_id=:run_id AND remediation IS NOT NULL
                ORDER BY control_id
            """), {"run_id": audit_run_id}
        )).mappings().all()
    return [_jsonable(row) for row in rows]


def _jsonable(row) -> dict:
    value = json.loads(json.dumps(dict(row), default=str))
    if isinstance(value.get("risk_flags"), str):
        value["risk_flags"] = json.loads(value["risk_flags"])
    return value
