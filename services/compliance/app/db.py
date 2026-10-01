"""
Postgres access for compliance findings. This lane owns the
`compliance_findings` table (see infra/postgres/init.sql) and updates
`audit_runs.status`; the row itself is created by Ingestion.

Mirrors services/ingestion/app/db.py's connection pattern for the shared
Postgres instance.
"""

import json

from app import waivers as waivers_module
import hashlib
import os
from datetime import datetime, timezone

from sqlalchemy import bindparam, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

POSTGRES_DSN = os.getenv(
    "POSTGRES_DSN",
    "postgresql+asyncpg://netaudit:changeme_in_local_env@postgres:5432/netaudit",
)

# Set once compliance has written its findings for a run. Reporting picks the
# run up from here; the run only becomes COMPLETE after the PDF is generated.
STATUS_EVALUATED = "EVALUATED"
POLICY_BUNDLE_VERSION = os.getenv("POLICY_BUNDLE_VERSION", "cis-generic-level1@1.0.0")

# NullPool: this module is imported once, but each Celery task runs in its
# own asyncio.run() call — a fresh event loop every time. A pooled
# connection created on one loop and reused on the next raises "Future
# attached to a different loop" / "another operation is in progress".
engine = create_async_engine(POSTGRES_DSN, echo=False, poolclass=NullPool)
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
    parser_agreement: float | None = None,
    deterministic_baseline: dict | None = None,
) -> list[dict]:
    """Replace this run's findings and mark it EVALUATED, in one transaction.

    Replace rather than append: re-running an audit after a policy update must
    not leave findings for controls that no longer fail. The immutable trail
    the blueprint calls for lives in `audit_runs`, not here.

    Returns the findings that were genuinely new this call (a real first
    VIOLATION_DETECTED was recorded for them) — app/webhooks.py's caller
    (app/evaluator.py) uses this so a re-evaluation of an already-known,
    still-failing control doesn't re-notify a ticketing system that's
    already tracking it.
    """
    newly_detected: list[dict] = []
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
                # MTTR (docs/Additional-Features.md §5) measures from first
                # detection, so a re-evaluation after a policy-bundle update
                # (this run's findings were just deleted and reinserted
                # above) must not reset a still-failing control's clock —
                # only record VIOLATION_DETECTED for a (run, control) pair
                # that has never had one before. One statement per finding
                # (not a set-based json_to_recordset insert) so this stays
                # plain, dialect-neutral SQL for the SQLite-backed tests.
                for f in findings:
                    if not f.get("control_id"):
                        continue
                    result = await session.execute(
                        text(
                            """
                            INSERT INTO ledger_events (audit_run_id, control_id, event_type, actor, ruleset_version, payload)
                            SELECT :audit_run_id, :control_id, 'VIOLATION_DETECTED', 'system', :ruleset_version, :payload
                            WHERE NOT EXISTS (
                                SELECT 1 FROM ledger_events
                                WHERE audit_run_id = :audit_run_id AND control_id = :control_id
                                  AND event_type = 'VIOLATION_DETECTED'
                            )
                            """
                        ),
                        {
                            "audit_run_id": audit_run_id,
                            "control_id": f["control_id"],
                            "ruleset_version": POLICY_BUNDLE_VERSION,
                            "payload": json.dumps({"severity": f.get("severity"), "title": f.get("title")}),
                        },
                    )
                    if result.rowcount:
                        newly_detected.append(f)
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
                            baseline_snapshot=:baseline, mean_logprob=:mean_logprob,
                            reverse_translation_fidelity=:reverse_translation_fidelity,
                            parser_agreement=:parser_agreement,
                            deterministic_baseline=:deterministic_baseline
                            WHERE id=:run_id
                        """
                    ),
                    {
                        "vendor": device.get("detected_vendor"),
                        "detected_os": device.get("detected_os"),
                        "confidence": device.get("parsing_confidence"),
                        "schema_version": baseline.get("schema_version"),
                        "baseline": canonical,
                        "mean_logprob": device.get("mean_logprob"),
                        "reverse_translation_fidelity": device.get("reverse_translation_fidelity"),
                        "parser_agreement": parser_agreement,
                        "deterministic_baseline": json.dumps(deterministic_baseline) if deterministic_baseline is not None else None,
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
    return newly_detected


async def get_findings_by_run() -> dict[str, list[dict]]:
    """Every EVALUATED/COMPLETE run's findings, grouped by audit_run_id — the
    input risk_scorer.fleet_score needs for docs/Additional-Features.md §1's
    fleet-wide rollup. Each audit_run_id here stands in for one device
    instance (see app/db.py's module docstring elsewhere in this codebase
    for why there's no separate persistent device identity to group by
    instead)."""
    async with async_session() as session:
        run_ids = (
            await session.execute(
                text("SELECT id FROM audit_runs WHERE status IN ('EVALUATED', 'COMPLETE')")
            )
        ).scalars().all()
        if not run_ids:
            return {}
        rows = (
            await session.execute(
                text("SELECT audit_run_id, control_id, severity FROM compliance_findings WHERE audit_run_id IN :run_ids")
                .bindparams(bindparam("run_ids", expanding=True)),
                {"run_ids": run_ids},
            )
        ).mappings().all()
    by_run: dict[str, list[dict]] = {str(run_id): [] for run_id in run_ids}
    for row in rows:
        by_run[str(row["audit_run_id"])].append({"control_id": row["control_id"], "severity": row["severity"]})
    return by_run


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


async def get_trust_data(audit_run_id: str) -> dict | None:
    """docs/Suggestions.md item 7 / docs/action.md Phase 3 — the two raw
    baselines app/trust.py diffs. None when the run doesn't exist."""
    async with async_session() as session:
        row = (await session.execute(
            text("SELECT baseline_snapshot, deterministic_baseline, parser_agreement "
                 "FROM audit_runs WHERE id=:run_id"),
            {"run_id": audit_run_id},
        )).mappings().first()
    if row is None:
        return None
    value = dict(row)
    for field in ("baseline_snapshot", "deterministic_baseline"):
        if isinstance(value.get(field), str):
            value[field] = json.loads(value[field])
    return value


async def get_ledger_events() -> list[dict]:
    """Every ledger event, oldest first, in the exact form app/ledger_seal.py
    hashes (strings for ids/timestamps, payload as an object)."""
    async with async_session() as session:
        rows = (await session.execute(text(
            "SELECT id, audit_run_id, control_id, event_type, actor, ruleset_version, payload, created_at "
            "FROM ledger_events ORDER BY created_at, id"
        ))).mappings().all()
    events = []
    for row in rows:
        event = dict(row)
        for field in ("id", "audit_run_id", "created_at"):
            event[field] = str(event[field])
        if isinstance(event.get("payload"), str):
            event["payload"] = json.loads(event["payload"])
        events.append(event)
    return events


async def get_ledger_seals() -> list[dict]:
    async with async_session() as session:
        rows = (await session.execute(text(
            "SELECT seq, merkle_root, prev_seal_hash, event_count, sealed_at, signature, key_id, event_ids "
            "FROM ledger_seals ORDER BY seq"
        ))).mappings().all()
    seals = []
    for row in rows:
        seal = dict(row)
        if isinstance(seal["event_ids"], str):
            seal["event_ids"] = json.loads(seal["event_ids"])
        seals.append(seal)
    return seals


async def insert_ledger_seal(seal: dict) -> None:
    """Primary-key on seq makes two concurrent sealers collide instead of forking the chain."""
    async with async_session() as session, session.begin():
        await session.execute(
            text("INSERT INTO ledger_seals (seq, merkle_root, prev_seal_hash, event_count, sealed_at, signature, key_id, event_ids) "
                 "VALUES (:seq, :merkle_root, :prev_seal_hash, :event_count, :sealed_at, :signature, :key_id, :event_ids)"),
            {**seal, "event_ids": json.dumps(seal["event_ids"])},
        )


async def get_waiver_events() -> list[dict]:
    """Waiver grants and revocations from the ledger, oldest first."""
    async with async_session() as session:
        rows = (await session.execute(text(
            "SELECT id, audit_run_id, control_id, event_type, actor, payload, created_at FROM ledger_events "
            "WHERE event_type IN ('WAIVER_GRANTED', 'WAIVER_REVOKED') ORDER BY created_at, id"))).mappings().all()
    events = []
    for row in rows:
        event = dict(row)
        for field in ("id", "audit_run_id", "created_at"):
            event[field] = str(event[field])
        if isinstance(event.get("payload"), str):
            event["payload"] = json.loads(event["payload"])
        events.append(event)
    return events


async def insert_waiver_event(event_id: str, audit_run_id: str, control_id: str, event_type: str, actor: str, payload: dict) -> None:
    """Append-only, like every ledger write: a waiver is never edited, only superseded or revoked."""
    async with async_session() as session, session.begin():
        await session.execute(
            text("INSERT INTO ledger_events (id, audit_run_id, control_id, event_type, actor, ruleset_version, payload) "
                 "VALUES (:id, :run, :control, :type, :actor, :version, :payload)"),
            {"id": event_id, "run": audit_run_id, "control": control_id, "type": event_type, "actor": actor,
             "version": POLICY_BUNDLE_VERSION, "payload": json.dumps(payload)},
        )


async def get_device_risk_by_hash() -> dict[str, dict]:
    """{config hash: latest evaluated run's score/findings}. A topology Device node is
    keyed by config_sha256, which is the audit run's file_hash."""
    from app.risk_scorer import summarize
    async with async_session() as session:
        runs = (await session.execute(text(
            "SELECT id, file_hash, original_filename, created_at FROM audit_runs "
            "WHERE status IN (:evaluated, 'COMPLETE') ORDER BY created_at"), {"evaluated": STATUS_EVALUATED})).mappings().all()
        findings = (await session.execute(text("SELECT audit_run_id, control_id, severity, title FROM compliance_findings"))).mappings().all()
    by_run: dict[str, list[dict]] = {}
    for row in findings:
        by_run.setdefault(str(row["audit_run_id"]), []).append(dict(row))
    latest: dict[str, dict] = {}
    for run in runs:  # oldest first, so the newest audit of a file wins
        run_findings = by_run.get(str(run["id"]), [])
        summary = summarize(run_findings)
        latest[run["file_hash"]] = {
            "audit_run_id": str(run["id"]), "filename": run["original_filename"],
            "compliance_score": summary["compliance_score"], "total_findings": summary["total_findings"],
            "critical": summary["by_severity"].get("CRITICAL", 0),
        }
    return latest


async def get_device_runs(audit_run_id: str, limit: int = 200) -> list[dict]:
    """Every evaluated run of the same device as `audit_run_id` (same vendor
    and raw_hostname in the stored baseline), oldest first, each with its
    findings — the input to app/drift.py. Filtering by hostname happens in
    Python because the JSON operators differ between Postgres and SQLite."""
    async with async_session() as session:
        anchor = (await session.execute(
            text("SELECT detected_vendor, baseline_snapshot FROM audit_runs WHERE id=:run_id"),
            {"run_id": audit_run_id},
        )).mappings().first()
        if anchor is None:
            return []
        candidates = (await session.execute(
            text("SELECT id, created_at, original_filename, detected_vendor, baseline_snapshot FROM audit_runs "
                 "WHERE status IN (:evaluated, 'COMPLETE') ORDER BY created_at LIMIT :limit"),
            {"evaluated": STATUS_EVALUATED, "limit": limit},
        )).mappings().all()

        def identity(vendor, snapshot):
            if isinstance(snapshot, str):
                snapshot = json.loads(snapshot)
            hostname = ((snapshot or {}).get("device") or {}).get("raw_hostname")
            return (vendor or "").lower(), (hostname or "").lower()

        target = identity(anchor["detected_vendor"], anchor["baseline_snapshot"])
        if not target[1]:
            same = [r for r in candidates if str(r["id"]) == audit_run_id]
        else:
            same = [r for r in candidates if identity(r["detected_vendor"], r["baseline_snapshot"]) == target]
        ids = [str(r["id"]) for r in same]
        findings_by_run: dict[str, list[dict]] = {run_id: [] for run_id in ids}
        if ids:
            rows = (await session.execute(
                text("SELECT audit_run_id, control_id, severity, title FROM compliance_findings "
                     "WHERE audit_run_id IN :ids").bindparams(bindparam("ids", expanding=True)),
                {"ids": ids},
            )).mappings().all()
            for row in rows:
                findings_by_run[str(row["audit_run_id"])].append(dict(row))
    return [
        {"run_id": str(r["id"]), "created_at": str(r["created_at"]), "filename": r["original_filename"],
         "findings": findings_by_run[str(r["id"])]}
        for r in same
    ]


async def list_evaluated_run_ids(limit: int = 20) -> list[str]:
    """Newest evaluated runs first — the server-side source for the UI's device
    inventory, so it survives a cleared browser."""
    async with async_session() as session:
        rows = (await session.execute(
            text("SELECT id FROM audit_runs WHERE status IN (:evaluated, 'COMPLETE') ORDER BY created_at DESC LIMIT :limit"),
            {"evaluated": STATUS_EVALUATED, "limit": limit},
        )).all()
    return [str(r[0]) for r in rows]


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
                           mean_logprob, reverse_translation_fidelity, parser_agreement,
                           baseline_snapshot, created_at, updated_at
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
    snapshot = result.pop("baseline_snapshot", None)
    if isinstance(snapshot, str):
        snapshot = json.loads(snapshot)
    identity = (snapshot or {}).get("device") or {}
    result["device_key"] = waivers_module.device_key(result.get("detected_vendor"), identity.get("raw_hostname"), result.get("file_hash"))
    result["device"] = {
        "hostname": identity.get("raw_hostname"),
        "detected_os_version": identity.get("detected_os_version"),
        "hardware_model": identity.get("detected_hardware_model"),
        "serial_number": identity.get("serial_number"),
        "detected_vendor": result.pop("detected_vendor", None),
        "detected_os": result.pop("detected_os", None),
        "parsing_confidence": result.pop("parsing_confidence", None),
        "mean_logprob": result.pop("mean_logprob", None),
        "reverse_translation_fidelity": result.pop("reverse_translation_fidelity", None),
        "parser_agreement": result.pop("parser_agreement", None),
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
