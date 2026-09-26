"""
Unit tests for app.db against an in-memory SQLite database standing in for
Postgres — same approach as services/compliance/tests/test_db.py. Exercises
the approval matrix (docs/Additional-Features.md §7) and rollback lifecycle
(§3) end-to-end against real SQL, since this service otherwise only tests
db.py indirectly through mocked calls in test_main.py.
"""

import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app import db
from app.approval_matrix import ApprovalDenied

RUN_ID = "11111111-1111-1111-1111-111111111111"


def _proposal(control_id="CIS-NET-1.1.2", decision_action="SINGLE_APPROVAL", risk_tier="LOW", blast_radius_count=0, preflight_status="SAFE"):
    return {
        "audit_run_id": RUN_ID, "control_id": control_id, "template_name": "fix.j2", "script": "fix it",
        "rollback_script": None, "source": "template",
        "preflight": {"status": preflight_status, "risk_flags": []},
        "decision": {"action": decision_action, "rule_id": "r1", "ruleset_version": "1.0.0", "risk": risk_tier, "blast_radius_count": blast_radius_count},
    }


@pytest_asyncio.fixture
async def sqlite_session(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")

    async with engine.begin() as conn:
        await conn.execute(text(
            """
            CREATE TABLE audit_evaluations (
                audit_run_id TEXT NOT NULL, baseline_sha256 TEXT NOT NULL, evaluated_at TEXT
            )
            """
        ))
        await conn.execute(text(
            """
            CREATE TABLE compliance_findings (
                audit_run_id TEXT NOT NULL, control_id TEXT NOT NULL, blast_radius TEXT NOT NULL DEFAULT '[]'
            )
            """
        ))
        await conn.execute(text(
            """
            CREATE TABLE remediation_proposals (
                audit_run_id TEXT NOT NULL, control_id TEXT NOT NULL,
                template_name TEXT NOT NULL, script TEXT NOT NULL, rollback_script TEXT,
                source TEXT NOT NULL DEFAULT 'template',
                preflight_status TEXT NOT NULL, risk_flags TEXT NOT NULL DEFAULT '[]',
                decision_action TEXT, decision_rule_id TEXT, decision_ruleset_version TEXT,
                risk_tier TEXT, blast_radius_count INTEGER NOT NULL DEFAULT 0,
                approval_status TEXT NOT NULL DEFAULT 'PENDING',
                approved_by TEXT, approval_comment TEXT, approved_at TEXT,
                pre_change_baseline_sha256 TEXT, applied_at TEXT,
                rollback_status TEXT NOT NULL DEFAULT 'NONE',
                created_at TEXT, updated_at TEXT,
                PRIMARY KEY (audit_run_id, control_id)
            )
            """
        ))
        await conn.execute(text(
            """
            CREATE TABLE ledger_events (
                id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
                audit_run_id TEXT NOT NULL, control_id TEXT, event_type TEXT NOT NULL,
                actor TEXT NOT NULL DEFAULT 'system', ruleset_version TEXT,
                payload TEXT NOT NULL DEFAULT '{}', created_at TEXT
            )
            """
        ))
        await conn.execute(
            text("INSERT INTO audit_evaluations (audit_run_id, baseline_sha256, evaluated_at) VALUES (:id, :sha, '2026-01-01T00:00:00Z')"),
            {"id": RUN_ID, "sha": "a" * 64},
        )

    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(db, "async_session", session_factory)

    yield session_factory

    await engine.dispose()


async def test_save_proposal_persists_decision_and_rbac_columns(sqlite_session):
    await db.save_proposal(_proposal(decision_action="DUAL_APPROVAL", risk_tier="HIGH", blast_radius_count=3))

    row = await db.get_proposal(RUN_ID, "CIS-NET-1.1.2")

    assert row["decision_action"] == "DUAL_APPROVAL"
    assert row["risk_tier"] == "HIGH"
    assert row["blast_radius_count"] == 3


async def test_operator_can_approve_a_low_risk_single_device_proposal(sqlite_session):
    await db.save_proposal(_proposal(decision_action="SINGLE_APPROVAL", risk_tier="LOW", blast_radius_count=0))

    result = await db.approve("CIS-NET-1.1.2", RUN_ID, True, "operator-1", None, "operator")

    assert result["approval_status"] == "APPROVED"
    assert result["approved_by"] == "operator-1"


async def test_operator_cannot_approve_a_high_risk_proposal(sqlite_session):
    await db.save_proposal(_proposal(decision_action="DUAL_APPROVAL", risk_tier="HIGH", blast_radius_count=1))

    try:
        await db.approve("CIS-NET-1.1.2", RUN_ID, True, "operator-1", None, "operator")
        assert False, "expected ApprovalDenied"
    except ApprovalDenied:
        pass

    row = await db.get_proposal(RUN_ID, "CIS-NET-1.1.2")
    assert row["approval_status"] == "PENDING"


async def test_dual_approval_requires_a_second_distinct_actor(sqlite_session):
    await db.save_proposal(_proposal(decision_action="DUAL_APPROVAL", risk_tier="HIGH", blast_radius_count=1))

    first = await db.approve("CIS-NET-1.1.2", RUN_ID, True, "admin-1", None, "admin")
    assert first["approval_status"] == "PENDING"
    assert first["dual_approval"] == {"required": 2, "received": 1}

    row = await db.get_proposal(RUN_ID, "CIS-NET-1.1.2")
    assert row["approval_status"] == "PENDING"

    second = await db.approve("CIS-NET-1.1.2", RUN_ID, True, "admin-2", None, "admin")
    assert second["approval_status"] == "APPROVED"
    assert second["dual_approval"] == {"required": 2, "received": 2}


async def test_dual_approval_rejects_the_same_actor_approving_twice(sqlite_session):
    await db.save_proposal(_proposal(decision_action="DUAL_APPROVAL", risk_tier="HIGH", blast_radius_count=1))

    await db.approve("CIS-NET-1.1.2", RUN_ID, True, "admin-1", None, "admin")
    second = await db.approve("CIS-NET-1.1.2", RUN_ID, True, "admin-1", None, "admin")

    assert second["approval_status"] == "PENDING"
    row = await db.get_proposal(RUN_ID, "CIS-NET-1.1.2")
    assert row["approval_status"] == "PENDING"


async def test_regenerating_the_script_invalidates_a_prior_approval_for_the_quorum(sqlite_session):
    """A stale APPROVED ledger event from a script version that's since been
    regenerated must never count toward the new version's DUAL_APPROVAL
    quorum — admin-1 approved v1, but never saw v2's actual commands."""
    await db.save_proposal(_proposal(decision_action="DUAL_APPROVAL", risk_tier="HIGH", blast_radius_count=1))
    first = await db.approve("CIS-NET-1.1.2", RUN_ID, True, "admin-1", None, "admin")
    assert first["dual_approval"] == {"required": 2, "received": 1}

    # Regenerate — a materially different script, same control/run.
    await db.save_proposal(_proposal(decision_action="DUAL_APPROVAL", risk_tier="HIGH", blast_radius_count=1))
    row = await db.get_proposal(RUN_ID, "CIS-NET-1.1.2")
    assert row["approval_status"] == "PENDING"

    second = await db.approve("CIS-NET-1.1.2", RUN_ID, True, "admin-2", None, "admin")
    assert second["approval_status"] == "PENDING"
    assert second["dual_approval"] == {"required": 2, "received": 1}


async def test_reject_is_not_role_restricted(sqlite_session):
    await db.save_proposal(_proposal(decision_action="DUAL_APPROVAL", risk_tier="HIGH", blast_radius_count=1))

    result = await db.approve("CIS-NET-1.1.2", RUN_ID, False, "operator-1", "not safe", "operator")

    assert result["approval_status"] == "REJECTED"


async def test_non_safe_proposal_cannot_be_approved(sqlite_session):
    await db.save_proposal(_proposal(preflight_status="RISK_FLAGS"))

    result = await db.approve("CIS-NET-1.1.2", RUN_ID, True, "admin-1", None, "admin")

    assert result is None


async def test_block_classification_cannot_be_approved_even_by_admin(sqlite_session):
    await db.save_proposal(_proposal(decision_action="BLOCK"))

    try:
        await db.approve("CIS-NET-1.1.2", RUN_ID, True, "admin-1", None, "admin")
        assert False, "expected ApprovalDenied"
    except ApprovalDenied:
        pass


async def test_apply_and_rollback_lifecycle(sqlite_session):
    await db.save_proposal(_proposal())
    await db.approve("CIS-NET-1.1.2", RUN_ID, True, "operator-1", None, "operator")

    applied = await db.mark_applied("CIS-NET-1.1.2", RUN_ID, "operator-1")
    assert applied["rollback_status"] == "APPLIED"

    rolled_back = await db.rollback("CIS-NET-1.1.2", RUN_ID, "operator-1", "broke connectivity", True)
    assert rolled_back["rollback_status"] == "ROLLED_BACK"

    async with sqlite_session() as session:
        events = (await session.execute(
            text("SELECT event_type FROM ledger_events WHERE audit_run_id=:id AND control_id='CIS-NET-1.1.2' ORDER BY rowid"),
            {"id": RUN_ID},
        )).scalars().all()
    assert events == ["REMEDIATION_PROPOSED", "DECISION_MADE", "APPROVED", "APPLIED", "VERIFICATION_FAILED", "ROLLED_BACK"]


async def test_rollback_without_a_prior_apply_is_a_no_op(sqlite_session):
    await db.save_proposal(_proposal())
    await db.approve("CIS-NET-1.1.2", RUN_ID, True, "operator-1", None, "operator")

    result = await db.rollback("CIS-NET-1.1.2", RUN_ID, "operator-1", "changed my mind", False)

    assert result is None
