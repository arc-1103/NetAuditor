"""
Unit tests for app.db against an in-memory SQLite database standing in for
Postgres — same approach as services/compliance/tests/test_db.py. Only
covers get_provenance_chain (docs/Suggestions.md item 5), since this is a
real four-table join with no existing coverage; the rest of db.py is
exercised indirectly through app/main.py, which pytest can't import here
(WeasyPrint has no native libgobject on this machine — pdf_service.py's
own docstring covers that gap). db.py itself has no WeasyPrint import, so
it's importable and testable on its own.
"""

import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app import db

RUN_ID = "11111111-1111-1111-1111-111111111111"
CONTROL_ID = "CIS-NET-1.1.2"


@pytest_asyncio.fixture
async def sqlite_session(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")

    async with engine.begin() as conn:
        await conn.execute(text(
            """
            CREATE TABLE compliance_findings (
                audit_run_id TEXT NOT NULL, control_id TEXT NOT NULL, framework TEXT,
                title TEXT, status TEXT, severity TEXT, evidence TEXT, remediation TEXT,
                risk_score INTEGER, blast_radius TEXT DEFAULT '[]', source_lines TEXT DEFAULT '[]'
            )
            """
        ))
        await conn.execute(text(
            """
            CREATE TABLE audit_evaluations (
                audit_run_id TEXT NOT NULL, framework TEXT, policy_bundle_version TEXT,
                schema_version TEXT, baseline_sha256 TEXT, evaluated_at TEXT
            )
            """
        ))
        await conn.execute(text(
            """
            CREATE TABLE remediation_proposals (
                audit_run_id TEXT NOT NULL, control_id TEXT NOT NULL, template_name TEXT, script TEXT,
                source TEXT, preflight_status TEXT, risk_flags TEXT DEFAULT '[]',
                decision_action TEXT, decision_ruleset_version TEXT, risk_tier TEXT,
                blast_radius_count INTEGER DEFAULT 0, approval_status TEXT, approved_by TEXT,
                approval_comment TEXT, approved_at TEXT, rollback_status TEXT
            )
            """
        ))
        await conn.execute(text(
            """
            CREATE TABLE ledger_events (
                audit_run_id TEXT NOT NULL, control_id TEXT, event_type TEXT,
                actor TEXT, ruleset_version TEXT, payload TEXT DEFAULT '{}', created_at TEXT
            )
            """
        ))

    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(db, "async_session", session_factory)

    yield session_factory

    await engine.dispose()


async def _insert(session_factory, table, **kwargs):
    columns = ", ".join(kwargs)
    placeholders = ", ".join(f":{k}" for k in kwargs)
    async with session_factory() as session, session.begin():
        await session.execute(text(f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"), kwargs)


async def test_provenance_chain_composes_finding_policy_remediation_and_events(sqlite_session):
    await _insert(sqlite_session, "compliance_findings",
        audit_run_id=RUN_ID, control_id=CONTROL_ID, framework="CIS", title="Telnet disabled",
        status="FAIL", severity="CRITICAL", evidence="telnet.enabled = ENABLED", remediation="ios_disable_telnet.j2",
        risk_score=40, blast_radius='["dev-2"]', source_lines='[{"line": 12, "text": "no telnet"}]')
    await _insert(sqlite_session, "audit_evaluations",
        audit_run_id=RUN_ID, framework="CIS", policy_bundle_version="cis-generic-level1@1.0.0",
        schema_version="1.0.0", baseline_sha256="a" * 64, evaluated_at="2026-01-01T00:00:00Z")
    await _insert(sqlite_session, "remediation_proposals",
        audit_run_id=RUN_ID, control_id=CONTROL_ID, template_name="ios_disable_telnet.j2", script="no telnet",
        source="template", preflight_status="SAFE", risk_flags="[]", decision_action="SINGLE_APPROVAL",
        decision_ruleset_version="1.0.0", risk_tier="HIGH", blast_radius_count=1,
        approval_status="APPROVED", approved_by="admin-1", approval_comment=None,
        approved_at="2026-01-01T02:00:00Z", rollback_status="NONE")
    await _insert(sqlite_session, "ledger_events",
        audit_run_id=RUN_ID, control_id=CONTROL_ID, event_type="VIOLATION_DETECTED",
        actor="system", ruleset_version="cis-generic-level1@1.0.0", payload="{}", created_at="2026-01-01T00:00:00Z")
    await _insert(sqlite_session, "ledger_events",
        audit_run_id=RUN_ID, control_id=CONTROL_ID, event_type="APPROVED",
        actor="admin-1", ruleset_version="1.0.0", payload="{}", created_at="2026-01-01T02:00:00Z")

    chain = await db.get_provenance_chain(RUN_ID, CONTROL_ID)

    assert chain["finding"]["title"] == "Telnet disabled"
    assert chain["finding"]["blast_radius"] == ["dev-2"]
    assert chain["policy"]["policy_bundle_version"] == "cis-generic-level1@1.0.0"
    assert chain["policy"]["baseline_sha256"] == "a" * 64
    assert chain["policy"]["rule_id"] == CONTROL_ID
    assert chain["remediation"]["approved_by"] == "admin-1"
    assert chain["remediation"]["script"] == "no telnet"
    assert [e["event_type"] for e in chain["events"]] == ["VIOLATION_DETECTED", "APPROVED"]


async def test_provenance_chain_of_an_unknown_finding_has_null_sections(sqlite_session):
    chain = await db.get_provenance_chain(RUN_ID, "NO-SUCH-CONTROL")

    assert chain["finding"] is None
    assert chain["remediation"] is None
    assert chain["events"] == []
