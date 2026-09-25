import json
import os
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.approval_matrix import ApprovalDenied, check_permission, dual_approval_satisfied

POSTGRES_DSN = os.getenv(
    "POSTGRES_DSN",
    "postgresql+asyncpg://netaudit:changeme_in_local_env@postgres:5432/netaudit",
)
engine = create_async_engine(POSTGRES_DSN, echo=False)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def save_proposal(proposal: dict) -> None:
    preflight = proposal["preflight"]
    decision = proposal.get("decision") or {}
    async with async_session() as session, session.begin():
        await session.execute(
            text("""
                INSERT INTO remediation_proposals
                    (audit_run_id, control_id, template_name, script, rollback_script, source,
                     preflight_status, risk_flags, decision_action, decision_rule_id,
                     decision_ruleset_version, risk_tier, blast_radius_count, approval_status, updated_at)
                VALUES (:audit_run_id, :control_id, :template_name, :script, :rollback_script, :source,
                        :preflight_status, :risk_flags, :decision_action, :decision_rule_id,
                        :decision_ruleset_version, :risk_tier, :blast_radius_count, 'PENDING', :updated_at)
                ON CONFLICT (audit_run_id, control_id) DO UPDATE SET
                    template_name = EXCLUDED.template_name,
                    script = EXCLUDED.script,
                    rollback_script = EXCLUDED.rollback_script,
                    source = EXCLUDED.source,
                    preflight_status = EXCLUDED.preflight_status,
                    risk_flags = EXCLUDED.risk_flags,
                    decision_action = EXCLUDED.decision_action,
                    decision_rule_id = EXCLUDED.decision_rule_id,
                    decision_ruleset_version = EXCLUDED.decision_ruleset_version,
                    risk_tier = EXCLUDED.risk_tier,
                    blast_radius_count = EXCLUDED.blast_radius_count,
                    approval_status = 'PENDING', approved_by = NULL,
                    approval_comment = NULL, approved_at = NULL,
                    applied_at = NULL, rollback_status = 'NONE',
                    updated_at = EXCLUDED.updated_at
            """),
            {
                **{k: proposal[k] for k in ("audit_run_id", "control_id", "template_name", "script")},
                "rollback_script": proposal.get("rollback_script"),
                "source": proposal.get("source", "template"),
                "preflight_status": preflight["status"],
                "risk_flags": json.dumps(preflight.get("risk_flags", [])),
                "decision_action": decision.get("action"),
                "decision_rule_id": decision.get("rule_id"),
                "decision_ruleset_version": decision.get("ruleset_version"),
                "risk_tier": decision.get("risk"),
                "blast_radius_count": decision.get("blast_radius_count", 0),
                "updated_at": datetime.now(timezone.utc),
            },
        )
        await _record_event(
            session, proposal["audit_run_id"], proposal["control_id"], "REMEDIATION_PROPOSED",
            actor="system", ruleset_version=None,
            payload={"source": proposal.get("source", "template"), "preflight_status": preflight["status"]},
        )
        if decision:
            await _record_event(
                session, proposal["audit_run_id"], proposal["control_id"], "DECISION_MADE",
                actor="system", ruleset_version=decision.get("ruleset_version"),
                payload={"action": decision.get("action"), "rule_id": decision.get("rule_id")},
            )


async def approve(control_id: str, audit_run_id: str, approved: bool, user_id: str, comment: str | None, role: str, actor_type: str = "human") -> dict | None:
    """docs/Additional-Features.md §7's approval matrix, layered on top of
    §2's preflight/decision gates. A rejection (approved=False) is never
    role-restricted, matching the existing behavior — only an actual
    approval is. Raises ApprovalDenied (caller maps to 403) when `role` may
    not give this approval at all; returns None for "not found" or
    "preflight not SAFE", same as before RBAC existed."""
    now = datetime.now(timezone.utc)

    if not approved:
        return await _finalize_approval(audit_run_id, control_id, "REJECTED", user_id, comment, now)

    async with async_session() as session:
        proposal = (await session.execute(
            text("""
                SELECT decision_action, decision_ruleset_version, risk_tier, blast_radius_count, preflight_status
                FROM remediation_proposals WHERE audit_run_id=:run_id AND control_id=:control_id
            """),
            {"run_id": audit_run_id, "control_id": control_id},
        )).mappings().first()
        if proposal is None or proposal["preflight_status"] != "SAFE":
            return None

        check_permission(
            role=role, decision_action=proposal["decision_action"] or "SINGLE_APPROVAL",
            risk=proposal["risk_tier"] or "HIGH", blast_radius_count=proposal["blast_radius_count"],
            actor_type=actor_type,
        )

        prior_actors = set((await session.execute(
            text("""
                SELECT DISTINCT actor FROM ledger_events
                WHERE audit_run_id=:run_id AND control_id=:control_id AND event_type='APPROVED'
            """),
            {"run_id": audit_run_id, "control_id": control_id},
        )).scalars().all())

    async with async_session() as session, session.begin():
        await _record_event(
            session, audit_run_id, control_id, "APPROVED", actor=user_id,
            ruleset_version=proposal["decision_ruleset_version"], payload={"comment": comment},
        )

    if not dual_approval_satisfied(proposal["decision_action"] or "SINGLE_APPROVAL", prior_actors, user_id):
        row = await get_proposal(audit_run_id, control_id)
        if row is not None:
            row["dual_approval"] = {"required": 2, "received": len(prior_actors | {user_id})}
        return row

    result = await _finalize_approval(audit_run_id, control_id, "APPROVED", user_id, comment, now)
    if result is not None:
        result["dual_approval"] = (
            {"required": 2, "received": len(prior_actors | {user_id})}
            if (proposal["decision_action"] or "") == "DUAL_APPROVAL" else None
        )
    return result


async def _finalize_approval(audit_run_id: str, control_id: str, status: str, user_id: str, comment: str | None, now: datetime) -> dict | None:
    async with async_session() as session, session.begin():
        pre_change_sha = (await session.execute(
            text("""
                SELECT baseline_sha256 FROM audit_evaluations
                WHERE audit_run_id = :run_id ORDER BY evaluated_at DESC LIMIT 1
            """),
            {"run_id": audit_run_id},
        )).scalar()
        approved = status == "APPROVED"
        row = (await session.execute(
            text("""
                UPDATE remediation_proposals
                SET approval_status=:status, approved_by=:user_id,
                    approval_comment=:comment, approved_at=:now, updated_at=:now,
                    pre_change_baseline_sha256 = CASE WHEN :approved THEN :pre_change_sha
                                                       ELSE pre_change_baseline_sha256 END
                WHERE audit_run_id=:run_id AND control_id=:control_id
                  AND (:approved = false OR preflight_status = 'SAFE')
                RETURNING audit_run_id, control_id, template_name, script, rollback_script, source,
                          preflight_status, risk_flags, decision_action, decision_rule_id,
                          decision_ruleset_version, risk_tier, blast_radius_count, approval_status,
                          approved_by, approval_comment, approved_at, pre_change_baseline_sha256,
                          applied_at, rollback_status
            """),
            {"status": status, "user_id": user_id, "comment": comment, "now": now,
             "run_id": audit_run_id, "control_id": control_id, "approved": approved,
             "pre_change_sha": pre_change_sha},
        )).mappings().first()
        if row is not None and not approved:
            # The approval case's own "APPROVED" event was already recorded
            # by the caller before dual-approval was known to be satisfied —
            # only record REJECTED here, so an approval is never double-logged.
            await _record_event(
                session, audit_run_id, control_id, status, actor=user_id,
                ruleset_version=row["decision_ruleset_version"], payload={"comment": comment},
            )
    return _jsonable(row) if row else None


async def get_proposal(audit_run_id: str, control_id: str) -> dict | None:
    async with async_session() as session:
        row = (await session.execute(
            text("""
                SELECT audit_run_id, control_id, template_name, script, rollback_script, source,
                       preflight_status, risk_flags, decision_action, decision_rule_id,
                       decision_ruleset_version, risk_tier, blast_radius_count, approval_status,
                       approved_by, approval_comment, approved_at, pre_change_baseline_sha256,
                       applied_at, rollback_status
                FROM remediation_proposals WHERE audit_run_id=:run_id AND control_id=:control_id
            """),
            {"run_id": audit_run_id, "control_id": control_id},
        )).mappings().first()
    return _jsonable(row) if row else None


async def mark_applied(control_id: str, audit_run_id: str, user_id: str) -> dict | None:
    """docs/Additional-Features.md §3: Approved -> Applied. There is no live
    device-push in this codebase — this records that an operator ran the
    approved script by hand, so post-change verification and rollback have
    a timestamp to measure and react against."""
    now = datetime.now(timezone.utc)
    async with async_session() as session, session.begin():
        row = (await session.execute(
            text("""
                UPDATE remediation_proposals
                SET applied_at=:now, rollback_status='APPLIED', updated_at=:now
                WHERE audit_run_id=:run_id AND control_id=:control_id AND approval_status='APPROVED'
                RETURNING audit_run_id, control_id, pre_change_baseline_sha256, applied_at, rollback_status
            """),
            {"now": now, "run_id": audit_run_id, "control_id": control_id},
        )).mappings().first()
        if row is not None:
            await _record_event(session, audit_run_id, control_id, "APPLIED", actor=user_id, ruleset_version=None, payload={})
    return _jsonable(row) if row else None


async def rollback(control_id: str, audit_run_id: str, user_id: str, reason: str, verification_failed: bool) -> dict | None:
    """docs/Additional-Features.md §3: restore is a stored pre-change hash,
    not a reconstructed guess — pre_change_baseline_sha256 was pinned at
    approval time. Restoring it to the live device is an operator action
    (see module docstring); this call marks the ledger's record of that
    decision, which is the part that must never be a silent event."""
    now = datetime.now(timezone.utc)
    async with async_session() as session, session.begin():
        if verification_failed:
            await _record_event(session, audit_run_id, control_id, "VERIFICATION_FAILED", actor=user_id, ruleset_version=None, payload={"reason": reason})
        row = (await session.execute(
            text("""
                UPDATE remediation_proposals
                SET rollback_status='ROLLED_BACK', updated_at=:now
                WHERE audit_run_id=:run_id AND control_id=:control_id AND applied_at IS NOT NULL
                RETURNING audit_run_id, control_id, pre_change_baseline_sha256, rollback_status
            """),
            {"now": now, "run_id": audit_run_id, "control_id": control_id},
        )).mappings().first()
        if row is not None:
            await _record_event(
                session, audit_run_id, control_id, "ROLLED_BACK", actor=user_id, ruleset_version=None,
                payload={"reason": reason, "restore_to_baseline_sha256": row["pre_change_baseline_sha256"]},
            )
    return _jsonable(row) if row else None


async def get_proposals(audit_run_id: str) -> list[dict]:
    async with async_session() as session:
        rows = (await session.execute(
            text("""
                SELECT audit_run_id, control_id, template_name, script, rollback_script, source,
                       preflight_status, risk_flags, decision_action, decision_rule_id,
                       decision_ruleset_version, risk_tier, blast_radius_count, approval_status,
                       approved_by, approval_comment, approved_at, pre_change_baseline_sha256,
                       applied_at, rollback_status, updated_at
                FROM remediation_proposals WHERE audit_run_id=:run_id
                ORDER BY control_id
            """), {"run_id": audit_run_id}
        )).mappings().all()
    return [_jsonable(row) for row in rows]


async def get_findings(audit_run_id: str) -> list[dict]:
    async with async_session() as session:
        rows = (await session.execute(
            text("""
                SELECT control_id, framework, title, severity, evidence, remediation, blast_radius
                FROM compliance_findings
                WHERE audit_run_id=:run_id AND remediation IS NOT NULL
                ORDER BY control_id
            """), {"run_id": audit_run_id}
        )).mappings().all()
    return [_jsonable(row) for row in rows]


async def get_run_parsing_confidence(audit_run_id: str) -> float | None:
    """The SLM's own self-reported confidence — app/decision.py's fallback
    when get_run_parser_agreement() below is None (an unsupported vendor,
    or a Parsing build from before docs/action.md Phase 2 shipped)."""
    async with async_session() as session:
        row = (await session.execute(
            text("SELECT parsing_confidence FROM audit_runs WHERE id=:run_id"),
            {"run_id": audit_run_id},
        )).first()
    return row[0] if row else None


async def get_run_parser_agreement(audit_run_id: str) -> float | None:
    """app/decision.py's real parser_agreement signal — docs/action.md
    Phase 2's swap of the proxy decision_table.yaml's header comment used
    to describe. Independent dual-parser agreement (Parsing's SLM vs. its
    TextFSM cross-check, services/parsing/app/agreement.py), not the SLM's
    own self-reported number. NULL when Parsing's deterministic extractor
    never covered this device's vendor — see get_run_parsing_confidence
    for the fallback that case uses."""
    async with async_session() as session:
        row = (await session.execute(
            text("SELECT parser_agreement FROM audit_runs WHERE id=:run_id"),
            {"run_id": audit_run_id},
        )).first()
    return row[0] if row else None


async def _record_event(session, audit_run_id: str, control_id: str | None, event_type: str, *, actor: str, ruleset_version: str | None, payload: dict) -> None:
    await session.execute(
        text("""
            INSERT INTO ledger_events (audit_run_id, control_id, event_type, actor, ruleset_version, payload)
            VALUES (:audit_run_id, :control_id, :event_type, :actor, :ruleset_version, :payload)
        """),
        {
            "audit_run_id": audit_run_id, "control_id": control_id, "event_type": event_type,
            "actor": actor or "system", "ruleset_version": ruleset_version, "payload": json.dumps(payload),
        },
    )


def _jsonable(row) -> dict:
    value = json.loads(json.dumps(dict(row), default=str))
    if isinstance(value.get("risk_flags"), str):
        value["risk_flags"] = json.loads(value["risk_flags"])
    if isinstance(value.get("blast_radius"), str):
        value["blast_radius"] = json.loads(value["blast_radius"])
    return value
