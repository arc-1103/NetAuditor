"""
Tests for the one wiring decision app/evaluator.py makes: persist only when
there is an AuditRun to persist against.
"""

from unittest.mock import AsyncMock

from app import evaluator

RUN_ID = "11111111-1111-1111-1111-111111111111"


def _stub_opa(monkeypatch, findings):
    monkeypatch.setattr(evaluator.opa_client, "evaluate", AsyncMock(return_value=findings))


def _stub_persistence(monkeypatch):
    """save_findings and save_anomaly both run whenever audit_run_id is
    given — mock both together so a test opting into persistence doesn't
    silently attempt a real DB write for whichever one it forgot."""
    save_findings = AsyncMock()
    save_anomaly = AsyncMock()
    monkeypatch.setattr(evaluator.db, "save_findings", save_findings)
    monkeypatch.setattr(evaluator.db, "save_anomaly", save_anomaly)
    return save_findings, save_anomaly


async def test_scores_findings_and_builds_summary(monkeypatch, baseline):
    _stub_opa(monkeypatch, [{"control_id": "CIS-IOS-1.1.2", "severity": "CRITICAL"}])
    _stub_persistence(monkeypatch)

    result = await evaluator.evaluate_baseline(baseline, "CIS", RUN_ID)

    assert result["findings"][0]["risk_score"] == 40
    assert result["summary"]["compliance_score"] == 60
    assert result["framework"] == "CIS"
    assert result["device"]["detected_vendor"] == "cisco"


async def test_persists_scored_findings_when_given_a_run_id(monkeypatch, baseline):
    _stub_opa(monkeypatch, [{"control_id": "CIS-IOS-1.1.2", "severity": "CRITICAL"}])
    save, _ = _stub_persistence(monkeypatch)

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


class FakeGraph:
    def __init__(self, blast_radius=None, fail=False):
        self.ingested = []
        self.blast_radius_calls = []
        self._blast_radius = blast_radius or []
        self._fail = fail

    async def ingest(self, baseline):
        if self._fail:
            raise RuntimeError("neo4j unavailable")
        self.ingested.append(baseline)

    async def blast_radius(self, device_id, *, max_hops):
        if self._fail:
            raise RuntimeError("neo4j unavailable")
        self.blast_radius_calls.append((device_id, max_hops))
        return self._blast_radius


async def test_attaches_blast_radius_to_every_finding_when_there_are_findings(monkeypatch, baseline):
    _stub_opa(monkeypatch, [{"control_id": "CIS-IOS-1.1.2", "severity": "CRITICAL"}])
    _stub_persistence(monkeypatch)
    graph = FakeGraph(blast_radius=["b" * 64, "c" * 64])

    result = await evaluator.evaluate_baseline(baseline, "CIS", RUN_ID, graph=graph)

    assert result["findings"][0]["blast_radius"] == ["b" * 64, "c" * 64]
    assert graph.ingested == [baseline]
    assert graph.blast_radius_calls == [(baseline["device"]["config_sha256"], evaluator.GRAPH_BLAST_RADIUS_MAX_HOPS)]


async def test_ingests_topology_but_skips_the_blast_radius_query_for_a_clean_device(monkeypatch, baseline):
    """A clean device still joins the routing graph (other devices' blast
    radius may traverse through it), but there's no finding to attach a
    blast radius to, so the query itself is skipped."""
    _stub_opa(monkeypatch, [])
    graph = FakeGraph(blast_radius=["should-not-be-queried"])

    result = await evaluator.evaluate_baseline(baseline, graph=graph)

    assert result["findings"] == []
    assert graph.ingested == [baseline]
    assert graph.blast_radius_calls == []


async def test_graph_outage_degrades_to_empty_blast_radius_not_a_failed_evaluation(monkeypatch, baseline):
    """Neo4j is optional enrichment, same as Parsing's RAG provider — an
    outage must not turn an evaluatable baseline into a failed compliance
    run."""
    _stub_opa(monkeypatch, [{"control_id": "CIS-IOS-1.1.2", "severity": "CRITICAL"}])
    _stub_persistence(monkeypatch)
    graph = FakeGraph(fail=True)

    result = await evaluator.evaluate_baseline(baseline, "CIS", RUN_ID, graph=graph)

    assert result["findings"][0]["blast_radius"] == []


# ── Lazy, failure-tolerant graph provider construction ───────────────
# A bad NEO4J_URI, a non-numeric GRAPH_BLAST_RADIUS_MAX_HOPS, or a missing
# `neo4j` package must never crash module import — that would take down the
# whole compliance API and Celery worker at startup.
def test_int_env_falls_back_to_default_on_an_invalid_value(monkeypatch):
    monkeypatch.setenv("SOME_INT", "not-a-number")
    assert evaluator._int_env("SOME_INT", 7) == 7


def test_int_env_uses_the_default_when_unset(monkeypatch):
    monkeypatch.delenv("SOME_INT", raising=False)
    assert evaluator._int_env("SOME_INT", 7) == 7


def test_int_env_parses_a_valid_value(monkeypatch):
    monkeypatch.setenv("SOME_INT", "9")
    assert evaluator._int_env("SOME_INT", 7) == 9


async def test_graph_provider_construction_failure_falls_back_to_the_empty_provider(monkeypatch, baseline):
    monkeypatch.setattr(evaluator, "_graph", None)

    def _boom() -> None:
        raise RuntimeError("bad NEO4J_URI scheme")

    monkeypatch.setattr(evaluator.graph_client, "build_topology_graph_provider", _boom)
    _stub_opa(monkeypatch, [])

    result = await evaluator.evaluate_baseline(baseline)

    assert isinstance(evaluator._graph, evaluator.graph_client.EmptyTopologyGraphProvider)
    assert result["findings"] == []


async def test_graph_provider_is_built_once_and_memoized(monkeypatch, baseline):
    monkeypatch.setattr(evaluator, "_graph", None)
    calls = []

    def _build():
        calls.append(1)
        return evaluator.graph_client.EmptyTopologyGraphProvider()

    monkeypatch.setattr(evaluator.graph_client, "build_topology_graph_provider", _build)
    _stub_opa(monkeypatch, [])

    await evaluator.evaluate_baseline(baseline)
    await evaluator.evaluate_baseline(baseline)

    assert len(calls) == 1


async def test_shutdown_graph_provider_closes_a_built_driver(monkeypatch):
    closed = []

    class FakeDriverProvider:
        async def close(self):
            closed.append(True)

    monkeypatch.setattr(evaluator, "_graph", FakeDriverProvider())

    await evaluator.shutdown_graph_provider()

    assert closed == [True]


async def test_shutdown_graph_provider_is_a_noop_when_never_built(monkeypatch):
    monkeypatch.setattr(evaluator, "_graph", None)

    await evaluator.shutdown_graph_provider()  # must not raise


# ── Unsupervised anomaly detection: separate from the verdict ────────
class FakeAnomaly:
    def __init__(self, result=None, fail=False):
        self.ingested = []
        self.checked = []
        self._result = result or {"status": "unavailable"}
        self._fail = fail

    async def ingest(self, baseline):
        if self._fail:
            raise RuntimeError("learning unavailable")
        self.ingested.append(baseline)

    async def check(self, baseline):
        if self._fail:
            raise RuntimeError("learning unavailable")
        self.checked.append(baseline)
        return self._result


async def test_anomaly_result_is_attached_but_never_touches_findings_or_score(monkeypatch, baseline):
    """The core safety requirement: an anomalous verdict must not change
    risk_score/compliance_score or appear inside `findings` — see
    app/anomaly_client.py for why (the same baseline can flip
    anomalous/not-anomalous over time as more peers get scanned, unlike a
    deterministic OPA finding)."""
    _stub_opa(monkeypatch, [{"control_id": "CIS-IOS-1.1.2", "severity": "CRITICAL"}])
    _stub_persistence(monkeypatch)
    anomaly = FakeAnomaly(result={"status": "scored", "is_anomaly": True, "anomaly_score": -0.3, "peer_count": 9})

    result = await evaluator.evaluate_baseline(baseline, "CIS", RUN_ID, anomaly=anomaly)

    assert result["anomaly"] == {"status": "scored", "is_anomaly": True, "anomaly_score": -0.3, "peer_count": 9}
    assert result["summary"]["compliance_score"] == 60  # unchanged by the anomaly verdict
    assert all("is_anomaly" not in f and "anomaly_score" not in f for f in result["findings"])
    assert anomaly.ingested == [baseline]
    assert anomaly.checked == [baseline]


async def test_anomaly_ingest_and_check_run_even_for_a_clean_device(monkeypatch, baseline):
    """A clean device is still a legitimate peer for its vendor+OS cohort —
    the same reasoning graph_client.py's topology ingest already applies."""
    _stub_opa(monkeypatch, [])
    anomaly = FakeAnomaly(result={"status": "insufficient_peers", "peer_count": 1})

    result = await evaluator.evaluate_baseline(baseline, anomaly=anomaly)

    assert result["anomaly"]["status"] == "insufficient_peers"
    assert anomaly.ingested == [baseline]


async def test_anomaly_outage_degrades_to_unavailable_not_a_failed_evaluation(monkeypatch, baseline):
    _stub_opa(monkeypatch, [{"control_id": "CIS-IOS-1.1.2", "severity": "CRITICAL"}])
    _stub_persistence(monkeypatch)
    anomaly = FakeAnomaly(fail=True)

    result = await evaluator.evaluate_baseline(baseline, "CIS", RUN_ID, anomaly=anomaly)

    assert result["anomaly"] == {"status": "unavailable"}
    assert result["findings"][0]["risk_score"] == 40  # compliance verdict is unaffected


async def test_anomaly_result_is_persisted_when_given_a_run_id(monkeypatch, baseline):
    _stub_opa(monkeypatch, [{"control_id": "CIS-IOS-1.1.2", "severity": "CRITICAL"}])
    _, save_anomaly = _stub_persistence(monkeypatch)
    anomaly = FakeAnomaly(result={"status": "scored", "is_anomaly": False, "anomaly_score": 0.1, "peer_count": 6})

    await evaluator.evaluate_baseline(baseline, "CIS", RUN_ID, anomaly=anomaly)

    save_anomaly.assert_awaited_once_with(
        RUN_ID, baseline["device"]["config_sha256"],
        {"status": "scored", "is_anomaly": False, "anomaly_score": 0.1, "peer_count": 6},
    )


async def test_anomaly_result_is_not_persisted_without_a_run_id(monkeypatch, baseline):
    _stub_opa(monkeypatch, [])
    anomaly = FakeAnomaly(result={"status": "scored", "is_anomaly": True, "anomaly_score": -0.1, "peer_count": 6})

    save_anomaly = AsyncMock()
    monkeypatch.setattr(evaluator.db, "save_anomaly", save_anomaly)

    await evaluator.evaluate_baseline(baseline, anomaly=anomaly)

    save_anomaly.assert_not_awaited()


async def test_anomaly_provider_construction_failure_falls_back_to_the_empty_provider(monkeypatch, baseline):
    monkeypatch.setattr(evaluator, "_anomaly", None)

    def _boom() -> None:
        raise RuntimeError("bad LEARNING_URL")

    monkeypatch.setattr(evaluator.anomaly_client, "build_anomaly_detection_provider", _boom)
    _stub_opa(monkeypatch, [])

    result = await evaluator.evaluate_baseline(baseline)

    assert isinstance(evaluator._anomaly, evaluator.anomaly_client.EmptyAnomalyDetectionProvider)
    assert result["anomaly"] == {"status": "unavailable"}


async def test_anomaly_provider_is_built_once_and_memoized(monkeypatch, baseline):
    monkeypatch.setattr(evaluator, "_anomaly", None)
    calls = []

    def _build():
        calls.append(1)
        return evaluator.anomaly_client.EmptyAnomalyDetectionProvider()

    monkeypatch.setattr(evaluator.anomaly_client, "build_anomaly_detection_provider", _build)
    _stub_opa(monkeypatch, [])

    await evaluator.evaluate_baseline(baseline)
    await evaluator.evaluate_baseline(baseline)

    assert len(calls) == 1
