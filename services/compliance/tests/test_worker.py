"""
Tests for the Celery task's payload handling. The evaluation itself is
covered by test_opa_client/test_risk_scorer/test_db — what matters here is
that a malformed job from the Parsing lane fails loudly instead of writing a
"zero findings" verdict.
"""

import asyncio
from unittest.mock import AsyncMock

import pytest

from app import worker

RUN_ID = "11111111-1111-1111-1111-111111111111"
BASELINE = {"device": {"detected_vendor": "cisco"}}


def test_task_is_registered_under_the_contract_name():
    """Parsing sends `compliance.evaluate_baseline` — renaming it silently
    breaks the hop, since Celery just queues the unknown task."""
    assert worker.evaluate_baseline.name == "compliance.evaluate_baseline"


def test_task_evaluates_and_returns_the_summary(monkeypatch):
    spy = AsyncMock(return_value={"findings": [], "summary": {"compliance_score": 60}})
    monkeypatch.setattr(worker, "run_evaluation", spy)

    result = worker.evaluate_baseline({"audit_run_id": RUN_ID, "framework": "CIS", "baseline": BASELINE})

    assert result == {"compliance_score": 60}
    spy.assert_awaited_once_with(BASELINE, "CIS", RUN_ID, source_text=None, parser_agreement=None, deterministic_baseline=None)


def test_task_defaults_the_framework_when_absent(monkeypatch):
    spy = AsyncMock(return_value={"summary": {}})
    monkeypatch.setattr(worker, "run_evaluation", spy)

    worker.evaluate_baseline({"audit_run_id": RUN_ID, "baseline": BASELINE})

    spy.assert_awaited_once_with(BASELINE, None, RUN_ID, source_text=None, parser_agreement=None, deterministic_baseline=None)


def test_task_rejects_a_job_without_an_audit_run_id():
    with pytest.raises(ValueError, match="audit_run_id"):
        worker.evaluate_baseline({"baseline": BASELINE})


def test_task_rejects_a_job_without_a_baseline():
    """No baseline is not an empty baseline — that would report a device with
    zero findings as fully compliant."""
    with pytest.raises(ValueError, match="baseline"):
        worker.evaluate_baseline({"audit_run_id": RUN_ID})


def test_task_rejects_a_non_object_baseline():
    with pytest.raises(ValueError, match="baseline"):
        worker.evaluate_baseline({"audit_run_id": RUN_ID, "baseline": "not-a-dict"})


def test_worker_reuses_one_event_loop_across_tasks(monkeypatch):
    """asyncio.run() opens a fresh loop and closes it on every call, which
    breaks the module-level asyncpg pool on the second task in a worker
    process (its connections stay bound to the first, now-closed loop). _run
    must actually execute every task on the same persistent loop instead."""
    seen_loops = []

    async def fake_run_evaluation(*args, **kwargs):
        seen_loops.append(asyncio.get_running_loop())
        return {"summary": {}}

    monkeypatch.setattr(worker, "run_evaluation", fake_run_evaluation)

    worker.evaluate_baseline({"audit_run_id": RUN_ID, "baseline": BASELINE})
    worker.evaluate_baseline({"audit_run_id": RUN_ID, "baseline": BASELINE})

    assert len(seen_loops) == 2
    assert seen_loops[0] is seen_loops[1] is worker._loop
    assert not worker._loop.is_closed()
