"""
The one compliance pass: OPA evaluate -> score -> GraphRAG/anomaly enrich ->
persist.

Lives on its own because both entry points run it — app/worker.py for the
async Celery path from Parsing, and app/main.py for the synchronous
POST /evaluate used in demos and integration tests.
"""

import logging
import os

from app import anomaly_client, db, evidence_locator, graph_client, opa_client, risk_scorer

logger = logging.getLogger(__name__)


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        logger.warning("Invalid %s=%r; using default %d", name, raw, default)
        return default


GRAPH_BLAST_RADIUS_MAX_HOPS = _int_env("GRAPH_BLAST_RADIUS_MAX_HOPS", 3)

_graph: graph_client.TopologyGraphProvider | None = None


def _get_graph_provider() -> graph_client.TopologyGraphProvider:
    """Lazy and memoized, so a bad NEO4J_URI or a missing `neo4j` package is
    discovered (and degraded past) on first use, not at import time. Built
    eagerly at module scope, this would crash the whole compliance API and
    Celery worker on startup — exactly the failure mode the optional
    enrichment design in graph_client.py's module docstring exists to avoid.
    """
    global _graph
    if _graph is None:
        try:
            _graph = graph_client.build_topology_graph_provider()
        except Exception as exc:
            logger.warning(
                "Failed to initialize the topology graph provider; disabling GraphRAG enrichment: %s", exc
            )
            _graph = graph_client.EmptyTopologyGraphProvider()
    return _graph


_anomaly: anomaly_client.AnomalyDetectionProvider | None = None


def _get_anomaly_provider() -> anomaly_client.AnomalyDetectionProvider:
    """Lazy and memoized, same reasoning as _get_graph_provider — a bad
    LEARNING_URL must not crash the whole compliance API at import time."""
    global _anomaly
    if _anomaly is None:
        try:
            _anomaly = anomaly_client.build_anomaly_detection_provider()
        except Exception as exc:
            logger.warning(
                "Failed to initialize the anomaly detection provider; disabling it: %s", exc
            )
            _anomaly = anomaly_client.EmptyAnomalyDetectionProvider()
    return _anomaly


async def shutdown_graph_provider() -> None:
    """Close the topology graph driver, if one was ever built. Call once
    from the app's shutdown handler (app/main.py) — a driver meant to live
    the whole process should be closed at exit, not per request."""
    if _graph is not None and hasattr(_graph, "close"):
        await _graph.close()


async def evaluate_baseline(
    baseline: dict,
    framework: str | None = None,
    audit_run_id: str | None = None,
    *,
    source_text: str | None = None,
    graph: graph_client.TopologyGraphProvider | None = None,
    anomaly: anomaly_client.AnomalyDetectionProvider | None = None,
) -> dict:
    """Evaluate one normalized baseline and return findings + summary.

    Persists only when `audit_run_id` is given — a caller checking a config
    without an AuditRun row (the standalone demo path) would otherwise trip
    the compliance_findings foreign key.
    """
    graph_provider = graph if graph is not None else _get_graph_provider()
    anomaly_provider = anomaly if anomaly is not None else _get_anomaly_provider()
    findings = risk_scorer.score_findings(await opa_client.evaluate(baseline, framework))

    device_id = (baseline.get("device") or {}).get("config_sha256")
    blast_radius: list[str] = []
    try:
        # Ingest runs for every device, findings or not — a clean device is
        # still a node in the routing graph other devices' blast radius may
        # traverse through. The blast-radius query itself only runs when
        # there is something to attach it to.
        await graph_provider.ingest(baseline)
        if findings and device_id:
            blast_radius = await graph_provider.blast_radius(device_id, max_hops=GRAPH_BLAST_RADIUS_MAX_HOPS)
    except Exception as exc:
        # GraphRAG enrichment is optional, same as Parsing's RAG/vendor
        # fingerprint providers — a Neo4j outage must not turn an
        # evaluatable baseline into a failed compliance run.
        logger.warning("Topology graph enrichment unavailable for %s: %s", device_id, exc)

    # Unsupervised anomaly detection: a separate statistical signal, never
    # folded into findings/risk_score/compliance_score — see
    # app/anomaly_client.py for why. Ingest runs for every device, findings
    # or not, same as the graph above — a clean device is still a valid peer
    # for its vendor+OS cohort.
    anomaly_result: dict = {"status": "unavailable"}
    try:
        await anomaly_provider.ingest(baseline)
        anomaly_result = await anomaly_provider.check(baseline)
    except Exception as exc:
        logger.warning("Anomaly detection unavailable for %s: %s", device_id, exc)

    findings = evidence_locator.attach(
        [{**f, "blast_radius": blast_radius} for f in findings], source_text
    )
    summary = risk_scorer.summarize(findings)

    if audit_run_id:
        await db.save_findings(
            audit_run_id,
            findings,
            baseline=baseline,
            framework=(framework or opa_client.DEFAULT_FRAMEWORK).upper(),
        )
        if device_id:
            await db.save_anomaly(audit_run_id, device_id, anomaly_result)

    return {
        "audit_run_id": audit_run_id,
        "framework": (framework or opa_client.DEFAULT_FRAMEWORK).upper(),
        "device": baseline.get("device", {}),
        "findings": findings,
        "summary": summary,
        "anomaly": anomaly_result,
    }
