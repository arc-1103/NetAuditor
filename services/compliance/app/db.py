"""
Postgres access for compliance findings. This lane owns the
`compliance_findings` table (see infra/postgres/init.sql) and updates
`audit_runs.status`; the row itself is created by Ingestion.

Mirrors services/ingestion/app/db.py's connection pattern for the shared
Postgres instance.
"""

import json
import os
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

POSTGRES_DSN = os.getenv(
    "POSTGRES_DSN",
    "postgresql+asyncpg://netaudit:changeme_in_local_env@postgres:5432/netaudit",
)

# Set once compliance has written its findings for a run. Reporting picks the
# run up from here; the run only becomes COMPLETE after the PDF is generated.
STATUS_EVALUATED = "EVALUATED"

engine = create_async_engine(POSTGRES_DSN, echo=False)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

_FINDING_COLUMNS = (
    "control_id", "framework", "title", "status", "severity", "evidence", "remediation", "risk_score",
    "blast_radius",
)


async def save_findings(audit_run_id: str, findings: list[dict]) -> None:
    """Replace this run's findings and mark it EVALUATED, in one transaction.

    Replace rather than append: re-running an audit after a policy update must
    not leave findings for controls that no longer fail. The immutable trail
    the blueprint calls for lives in `audit_runs`, not here.
    """
    async with async_session() as session:
        async with session.begin():
            await session.execute(
                text("DELETE FROM compliance_findings WHERE audit_run_id = :run_id"),
                {"run_id": audit_run_id},
            )
            if findings:
                await session.execute(
                    text(
                        """
                        INSERT INTO compliance_findings
                            (audit_run_id, control_id, framework, title, status,
                             severity, evidence, remediation, risk_score, blast_radius)
                        VALUES
                            (:audit_run_id, :control_id, :framework, :title, :status,
                             :severity, :evidence, :remediation, :risk_score, :blast_radius)
                        """
                    ),
                    [
                        {
                            "audit_run_id": audit_run_id,
                            **{c: f.get(c) for c in _FINDING_COLUMNS if c != "blast_radius"},
                            "blast_radius": json.dumps(f.get("blast_radius") or []),
                        }
                        for f in findings
                    ],
                )
            # updated_at is bound from Python rather than SQL now() so this
            # statement stays dialect-neutral for the SQLite-backed tests.
            await session.execute(
                text("UPDATE audit_runs SET status = :status, updated_at = :updated_at WHERE id = :run_id"),
                {
                    "status": STATUS_EVALUATED,
                    "updated_at": datetime.now(timezone.utc),
                    "run_id": audit_run_id,
                },
            )


async def save_anomaly(audit_run_id: str, device_id: str, anomaly: dict) -> None:
    """Upsert this run's unsupervised anomaly-detection result.

    A separate table from compliance_findings, not a column on it: this is
    a statistical signal that can change over time as more peer devices are
    scanned, with nothing about the baseline itself changing — see
    app/anomaly_client.py. Keeping it structurally apart from findings
    makes "never affects risk_score/compliance_score" a schema guarantee,
    not just a convention.
    """
    async with async_session() as session, session.begin():
        await session.execute(
            text(
                """
                INSERT INTO configuration_anomalies
                    (audit_run_id, device_id, status, is_anomaly, anomaly_score, peer_count, checked_at)
                VALUES
                    (:audit_run_id, :device_id, :status, :is_anomaly, :anomaly_score, :peer_count, :checked_at)
                ON CONFLICT (audit_run_id) DO UPDATE SET
                    device_id = EXCLUDED.device_id,
                    status = EXCLUDED.status,
                    is_anomaly = EXCLUDED.is_anomaly,
                    anomaly_score = EXCLUDED.anomaly_score,
                    peer_count = EXCLUDED.peer_count,
                    checked_at = EXCLUDED.checked_at
                """
            ),
            {
                "audit_run_id": audit_run_id,
                "device_id": device_id,
                "status": anomaly.get("status", "unavailable"),
                "is_anomaly": anomaly.get("is_anomaly"),
                "anomaly_score": anomaly.get("anomaly_score"),
                "peer_count": anomaly.get("peer_count"),
                "checked_at": datetime.now(timezone.utc),
            },
        )


async def get_audit_run(audit_run_id: str) -> dict | None:
    """The payload behind GET /api/audit-runs/{id} — run + its findings.

    Returns None when the run doesn't exist so the caller can 404 rather than
    hand the frontend an empty run that looks like a clean device.
    """
    async with async_session() as session:
        run_row = (
            await session.execute(
                text(
                    """
                    SELECT id, file_hash, original_filename, storage_path,
                           uploaded_by, status, status_detail, created_at, updated_at
                    FROM audit_runs WHERE id = :run_id
                    """
                ),
                {"run_id": audit_run_id},
            )
        ).mappings().first()

        if run_row is None:
            return None

        finding_rows = (
            await session.execute(
                text(
                    """
                    SELECT control_id, framework, title, status, severity,
                           evidence, remediation, risk_score, blast_radius, created_at
                    FROM compliance_findings
                    WHERE audit_run_id = :run_id
                    ORDER BY control_id
                    """
                ),
                {"run_id": audit_run_id},
            )
        ).mappings().all()

        anomaly_row = (
            await session.execute(
                text(
                    """
                    SELECT device_id, status, is_anomaly, anomaly_score, peer_count, checked_at
                    FROM configuration_anomalies
                    WHERE audit_run_id = :run_id
                    """
                ),
                {"run_id": audit_run_id},
            )
        ).mappings().first()

    return {
        **_jsonable(run_row),
        "findings": [_jsonable(r) for r in finding_rows],
        "anomaly": _jsonable(anomaly_row) if anomaly_row is not None else None,
    }


def _jsonable(row) -> dict:
    """UUID/datetime columns come back as objects; FastAPI needs them as
    strings, and status_detail needs to come back as an object, not the
    JSON-encoded string it's stored/bound as."""
    value = json.loads(json.dumps(dict(row), default=str))
    if isinstance(value.get("status_detail"), str):
        value["status_detail"] = json.loads(value["status_detail"])
    if isinstance(value.get("blast_radius"), str):
        value["blast_radius"] = json.loads(value["blast_radius"])
    return value
