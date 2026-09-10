"""
Postgres access for compliance findings. This lane owns the
`compliance_findings` table (see infra/postgres/init.sql) and updates
`audit_runs.status`; the row itself is created by Ingestion.

Mirrors services/ingestion/app/db.py's connection pattern for the shared
Postgres instance.
"""

import json
import hashlib
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
POLICY_BUNDLE_VERSION = os.getenv("POLICY_BUNDLE_VERSION", "cis-generic-level1@1.0.0")

engine = create_async_engine(POSTGRES_DSN, echo=False)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

_FINDING_COLUMNS = (
    "control_id", "framework", "title", "status", "severity", "evidence", "remediation", "risk_score",
    "blast_radius", "source_lines",
)


async def save_findings(
    audit_run_id: str,
    findings: list[dict],
    *,
    baseline: dict | None = None,
    framework: str = "CIS",
) -> None:
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
                             severity, evidence, remediation, risk_score, blast_radius, source_lines)
                        VALUES
                            (:audit_run_id, :control_id, :framework, :title, :status,
                             :severity, :evidence, :remediation, :risk_score, :blast_radius, :source_lines)
                        """
                    ),
                    [
                        {
                            "audit_run_id": audit_run_id,
                            **{c: f.get(c) for c in _FINDING_COLUMNS if c not in {"blast_radius", "source_lines"}},
                            "blast_radius": json.dumps(f.get("blast_radius") or []),
                            "source_lines": json.dumps(f.get("source_lines") or []),
                        }
                        for f in findings
                    ],
                )
            if baseline is not None:
                canonical = json.dumps(baseline, sort_keys=True, separators=(",", ":"))
                device = baseline.get("device", {})
                now = datetime.now(timezone.utc)
                await session.execute(
                    text(
                        """
                        INSERT INTO audit_evaluations
                            (audit_run_id, framework, policy_bundle_version, schema_version,
                             baseline_sha256, findings_snapshot, evaluated_at)
                        VALUES (:run_id, :framework, :policy_version, :schema_version,
                                :baseline_sha256, :findings, :evaluated_at)
                        """
                    ),
                    {
                        "run_id": audit_run_id,
                        "framework": framework,
                        "policy_version": POLICY_BUNDLE_VERSION,
                        "schema_version": baseline.get("schema_version"),
                        "baseline_sha256": hashlib.sha256(canonical.encode()).hexdigest(),
                        "findings": json.dumps(findings),
                        "evaluated_at": now,
                    },
                )
                await session.execute(
                    text(
                        """
                        UPDATE audit_runs SET detected_vendor=:vendor, detected_os=:detected_os,
                            parsing_confidence=:confidence, schema_version=:schema_version,
                            baseline_snapshot=:baseline WHERE id=:run_id
                        """
                    ),
                    {
                        "vendor": device.get("detected_vendor"),
                        "detected_os": device.get("detected_os"),
                        "confidence": device.get("parsing_confidence"),
                        "schema_version": baseline.get("schema_version"),
                        "baseline": canonical,
                        "run_id": audit_run_id,
                    },
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
                           uploaded_by, status, status_detail, detected_vendor,
                           detected_os, parsing_confidence, schema_version,
                           created_at, updated_at
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
                           evidence, remediation, risk_score, blast_radius, source_lines, created_at
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

    result = _jsonable(run_row)
    result["device"] = {
        "detected_vendor": result.pop("detected_vendor", None),
        "detected_os": result.pop("detected_os", None),
        "parsing_confidence": result.pop("parsing_confidence", None),
    }
    return {
        **result,
        "findings": [_jsonable(r) for r in finding_rows],
        "anomaly": _jsonable(anomaly_row) if anomaly_row is not None else None,
        "policy_bundle_version": POLICY_BUNDLE_VERSION,
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
    if isinstance(value.get("source_lines"), str):
        value["source_lines"] = json.loads(value["source_lines"])
    return value
