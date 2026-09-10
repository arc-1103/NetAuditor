"""
Unit tests for app.db against an in-memory SQLite database standing in for
Postgres — same approach as services/ingestion/tests/test_db.py. The
statements are plain SQL, not Postgres-specific, apart from `now()` which
SQLite also provides via a user function below.
"""

import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app import db

RUN_ID = "11111111-1111-1111-1111-111111111111"


def _finding(control_id, severity="HIGH", risk_score=20):
    return {
        "control_id": control_id,
        "framework": "CIS",
        "title": f"Control {control_id}",
        "status": "FAIL",
        "severity": severity,
        "evidence": "ssh.version = 1",
        "remediation": "ios_ssh_v2_fix.j2",
        "risk_score": risk_score,
    }


@pytest_asyncio.fixture
async def sqlite_session(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")

    async with engine.begin() as conn:
        await conn.execute(
            text(
                """
                CREATE TABLE audit_runs (
                    id                TEXT PRIMARY KEY,
                    file_hash         TEXT NOT NULL,
                    original_filename TEXT,
                    storage_path      TEXT NOT NULL,
                    uploaded_by       TEXT,
                    status            TEXT NOT NULL DEFAULT 'INGESTED',
                    status_detail     TEXT,
                    detected_vendor   TEXT,
                    detected_os       TEXT,
                    parsing_confidence REAL,
                    schema_version    TEXT,
                    baseline_snapshot TEXT,
                    created_at        TEXT,
                    updated_at        TEXT
                )
                """
            )
        )
        await conn.execute(
            text(
                """
                CREATE TABLE audit_evaluations (
                    id                    TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
                    audit_run_id          TEXT NOT NULL,
                    framework             TEXT NOT NULL,
                    policy_bundle_version TEXT NOT NULL,
                    schema_version        TEXT,
                    baseline_sha256       TEXT NOT NULL,
                    findings_snapshot     TEXT NOT NULL,
                    evaluated_at          TEXT
                )
                """
            )
        )
        await conn.execute(
            text(
                """
                CREATE TABLE compliance_findings (
                    audit_run_id TEXT NOT NULL,
                    control_id   TEXT NOT NULL,
                    framework    TEXT NOT NULL,
                    title        TEXT NOT NULL,
                    status       TEXT NOT NULL,
                    severity     TEXT NOT NULL,
                    evidence     TEXT,
                    remediation  TEXT,
                    risk_score   INTEGER NOT NULL DEFAULT 0,
                    blast_radius TEXT NOT NULL DEFAULT '[]',
                    source_lines TEXT NOT NULL DEFAULT '[]',
                    created_at   TEXT,
                    PRIMARY KEY (audit_run_id, control_id)
                )
                """
            )
        )
        await conn.execute(
            text(
                """
                CREATE TABLE configuration_anomalies (
                    audit_run_id  TEXT PRIMARY KEY,
                    device_id     TEXT NOT NULL,
                    status        TEXT NOT NULL,
                    is_anomaly    INTEGER,
                    anomaly_score REAL,
                    peer_count    INTEGER,
                    checked_at    TEXT
                )
                """
            )
        )
        await conn.execute(
            text(
                """
                INSERT INTO audit_runs (id, file_hash, original_filename, storage_path, status)
                VALUES (:id, :hash, 'edge-rtr.cfg', 'raw-configs/abc.cfg', 'INGESTED')
                """
            ),
            {"id": RUN_ID, "hash": "b" * 64},
        )

    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(db, "async_session", session_factory)

    yield session_factory

    await engine.dispose()


async def test_save_findings_inserts_rows_and_marks_run_evaluated(sqlite_session):
    await db.save_findings(RUN_ID, [_finding("CIS-IOS-1.1.1"), _finding("CIS-IOS-1.1.2", "CRITICAL", 40)])

    async with sqlite_session() as session:
        rows = (
            await session.execute(
                text("SELECT * FROM compliance_findings WHERE audit_run_id = :id ORDER BY control_id"),
                {"id": RUN_ID},
            )
        ).mappings().all()
        status = (
            await session.execute(text("SELECT status FROM audit_runs WHERE id = :id"), {"id": RUN_ID})
        ).scalar_one()

    assert [r["control_id"] for r in rows] == ["CIS-IOS-1.1.1", "CIS-IOS-1.1.2"]
    assert rows[1]["severity"] == "CRITICAL"
    assert rows[1]["risk_score"] == 40
    assert rows[0]["remediation"] == "ios_ssh_v2_fix.j2"
    assert status == db.STATUS_EVALUATED


async def test_save_findings_replaces_a_previous_evaluation(sqlite_session):
    """Re-running after a policy change must not leave findings for controls
    that no longer fail."""
    await db.save_findings(RUN_ID, [_finding("CIS-IOS-1.1.1"), _finding("CIS-IOS-1.1.2")])

    await db.save_findings(RUN_ID, [_finding("CIS-IOS-1.1.2")])

    async with sqlite_session() as session:
        rows = (
            await session.execute(
                text("SELECT control_id FROM compliance_findings WHERE audit_run_id = :id"), {"id": RUN_ID}
            )
        ).scalars().all()

    assert rows == ["CIS-IOS-1.1.2"]


async def test_save_findings_accepts_a_clean_device(sqlite_session):
    await db.save_findings(RUN_ID, [])

    async with sqlite_session() as session:
        count = (
            await session.execute(
                text("SELECT count(*) FROM compliance_findings WHERE audit_run_id = :id"), {"id": RUN_ID}
            )
        ).scalar_one()
        status = (
            await session.execute(text("SELECT status FROM audit_runs WHERE id = :id"), {"id": RUN_ID})
        ).scalar_one()

    assert count == 0
    assert status == db.STATUS_EVALUATED


async def test_save_findings_records_immutable_provenance_and_device_metadata(sqlite_session):
    baseline = {
        "schema_version": "1.0.0",
        "device": {
            "detected_vendor": "cisco",
            "detected_os": "IOS-XE",
            "parsing_confidence": 0.96,
            "config_sha256": "b" * 64,
        },
    }
    await db.save_findings(RUN_ID, [_finding("CIS-NET-1.1.1")], baseline=baseline, framework="CIS")
    await db.save_findings(RUN_ID, [], baseline=baseline, framework="CIS")

    async with sqlite_session() as session:
        history = (await session.execute(text("SELECT * FROM audit_evaluations"))).mappings().all()
        run = (await session.execute(text("SELECT * FROM audit_runs WHERE id=:id"), {"id": RUN_ID})).mappings().one()

    assert len(history) == 2
    assert history[0]["policy_bundle_version"] == db.POLICY_BUNDLE_VERSION
    assert len(history[0]["baseline_sha256"]) == 64
    assert run["detected_vendor"] == "cisco"
    assert run["parsing_confidence"] == 0.96


async def test_get_audit_run_returns_run_with_findings(sqlite_session):
    await db.save_findings(RUN_ID, [_finding("CIS-IOS-1.1.1")])

    run = await db.get_audit_run(RUN_ID)

    assert run["id"] == RUN_ID
    assert run["original_filename"] == "edge-rtr.cfg"
    assert run["status"] == db.STATUS_EVALUATED
    assert [f["control_id"] for f in run["findings"]] == ["CIS-IOS-1.1.1"]


async def test_get_audit_run_returns_none_for_unknown_run(sqlite_session):
    """None, not an empty run — an empty run reads as a clean device."""
    assert await db.get_audit_run("22222222-2222-2222-2222-222222222222") is None


async def test_get_audit_run_before_evaluation_has_no_findings(sqlite_session):
    run = await db.get_audit_run(RUN_ID)

    assert run["status"] == "INGESTED"
    assert run["findings"] == []


async def test_get_audit_run_surfaces_status_detail_from_parsing(sqlite_session):
    """A run Parsing marked NEEDS_REVIEW (see services/parsing/app/db.py) must
    not look identical to one still awaiting processing — status_detail is
    the only place the reason survives."""
    async with sqlite_session() as session:
        await session.execute(
            text(
                """
                UPDATE audit_runs SET status = 'NEEDS_REVIEW',
                    status_detail = '{"reason": "unknown_or_unsupported_vendor", "detected_vendor": "unknown"}'
                WHERE id = :id
                """
            ),
            {"id": RUN_ID},
        )
        await session.commit()

    run = await db.get_audit_run(RUN_ID)

    assert run["status"] == "NEEDS_REVIEW"
    assert run["status_detail"] == {"reason": "unknown_or_unsupported_vendor", "detected_vendor": "unknown"}


async def test_blast_radius_round_trips_as_a_list(sqlite_session):
    """GraphRAG's blast_radius (app/graph_client.py) is stored as JSON and
    must come back as a list, not the JSON-encoded string it's bound as."""
    finding = _finding("CIS-IOS-1.1.1")
    finding["blast_radius"] = ["deadbeef" * 8, "cafebabe" * 8]
    await db.save_findings(RUN_ID, [finding])

    run = await db.get_audit_run(RUN_ID)

    assert run["findings"][0]["blast_radius"] == ["deadbeef" * 8, "cafebabe" * 8]


async def test_blast_radius_defaults_to_empty_list_when_absent(sqlite_session):
    """A finding scored before GraphRAG enrichment ran (or from a caller that
    doesn't set it) must not fail to insert — it just gets no blast radius."""
    await db.save_findings(RUN_ID, [_finding("CIS-IOS-1.1.1")])

    run = await db.get_audit_run(RUN_ID)

    assert run["findings"][0]["blast_radius"] == []


async def test_get_audit_run_anomaly_is_none_when_never_checked(sqlite_session):
    """A run compliance evaluated before the anomaly provider was configured
    (or that never reached the check) must not look like a scored 'not
    anomalous' verdict — it has no anomaly signal at all."""
    run = await db.get_audit_run(RUN_ID)

    assert run["anomaly"] is None


async def test_save_anomaly_inserts_a_scored_result(sqlite_session):
    await db.save_anomaly(
        RUN_ID, "a" * 64, {"status": "scored", "is_anomaly": True, "anomaly_score": -0.12, "peer_count": 8}
    )

    run = await db.get_audit_run(RUN_ID)

    assert run["anomaly"]["device_id"] == "a" * 64
    assert run["anomaly"]["status"] == "scored"
    # SQLite has no native boolean type, so the test harness's raw driver
    # returns 0/1 here — Postgres's real BOOLEAN column deserializes to
    # True/False via asyncpg before this same _jsonable() pass runs.
    assert run["anomaly"]["is_anomaly"] in (True, 1)
    assert run["anomaly"]["anomaly_score"] == -0.12
    assert run["anomaly"]["peer_count"] == 8


async def test_save_anomaly_upserts_by_audit_run_id(sqlite_session):
    """Re-evaluating a run must replace its anomaly result, not accumulate a
    second row for the same audit_run_id."""
    await db.save_anomaly(RUN_ID, "a" * 64, {"status": "insufficient_peers", "peer_count": 2})
    await db.save_anomaly(
        RUN_ID, "a" * 64, {"status": "scored", "is_anomaly": False, "anomaly_score": 0.1, "peer_count": 6}
    )

    run = await db.get_audit_run(RUN_ID)

    assert run["anomaly"]["status"] == "scored"
    assert run["anomaly"]["peer_count"] == 6


async def test_save_anomaly_defaults_missing_fields_to_none(sqlite_session):
    """insufficient_peers/not_ingested/unavailable carry no is_anomaly or
    anomaly_score — that must not fail the insert."""
    await db.save_anomaly(RUN_ID, "a" * 64, {"status": "insufficient_peers", "peer_count": 3})

    run = await db.get_audit_run(RUN_ID)

    assert run["anomaly"]["status"] == "insufficient_peers"
    assert run["anomaly"]["is_anomaly"] is None
    assert run["anomaly"]["anomaly_score"] is None
