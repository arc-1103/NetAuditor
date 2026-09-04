"""
Tests for the one wiring decision app/evaluator.py makes: persist only when
there is an AuditRun to persist against.
"""

from unittest.mock import AsyncMock

from app import evaluator

RUN_ID = "11111111-1111-1111-1111-111111111111"


def _stub_opa(monkeypatch, findings):
    monkeypatch.setattr(evaluator.opa_client, "evaluate", AsyncMock(return_value=findings))


async def test_scores_findings_and_builds_summary(monkeypatch, baseline):
    _stub_opa(monkeypatch, [{"control_id": "CIS-IOS-1.1.2", "severity": "CRITICAL"}])
    monkeypatch.setattr(evaluator.db, "save_findings", AsyncMock())

    result = await evaluator.evaluate_baseline(baseline, "CIS", RUN_ID)

    assert result["findings"][0]["risk_score"] == 40
    assert result["summary"]["compliance_score"] == 60
    assert result["framework"] == "CIS"
    assert result["device"]["detected_vendor"] == "cisco"


async def test_persists_scored_findings_when_given_a_run_id(monkeypatch, baseline):
    _stub_opa(monkeypatch, [{"control_id": "CIS-IOS-1.1.2", "severity": "CRITICAL"}])
    save = AsyncMock()
    monkeypatch.setattr(evaluator.db, "save_findings", save)

    await evaluator.evaluate_baseline(baseline, "CIS", RUN_ID)

    run_id, saved = save.await_args.args
    assert run_id == RUN_ID
    assert saved[0]["risk_score"] == 40  # scored, not raw


async def test_skips_persistence_without_a_run_id(monkeypatch, baseline):
    """The dry-run path — no AuditRun row exists, so an INSERT would trip the
    compliance_findings foreign key."""
    _stub_opa(monkeypatch, [])
    save = AsyncMock()
    monkeypatch.setattr(evaluator.db, "save_findings", save)

    result = await evaluator.evaluate_baseline(baseline)

    save.assert_not_awaited()
    assert result["audit_run_id"] is None
