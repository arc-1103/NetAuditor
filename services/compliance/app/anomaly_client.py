"""
Unsupervised semantic anomaly detection.

Vectorizes each evaluated baseline via Learning's embedding model
(services/learning/backend/app/embeddings.py) and flags "configuration
drift" — a device whose normalized security settings sit unusually far
from its vendor+OS peer cohort in embedding space — using an Isolation
Forest fit on the peer cohort (services/learning/backend/app/main.py's
check_baseline_anomaly).

This is a statistical signal, not a compliance verdict, and it is
deliberately kept separate from both: README.md states "the same
normalized baseline always produces the same verdict," but an
IsolationForest fit on an evolving peer cohort is not stable over time —
the same baseline could flip between anomalous/not-anomalous purely
because more peers have since been scanned, with nothing about the
baseline itself changing. For that reason app/evaluator.py surfaces this
as a separate `anomaly` field on the evaluate response and in its own
`configuration_anomalies` table — never folded into `findings`,
`risk_score`, or `compliance_score` — the same way `blast_radius`
(graph_client.py) is attached as context on top of a finding OPA already
decided, not as part of the decision itself.

Optional enrichment, not a compliance gate — same resilience pattern as
graph_client.py and Parsing's RAG/vendor-fingerprint providers.
"""

from __future__ import annotations

import os
from typing import Any, Protocol

import httpx


class AnomalyDetectionProvider(Protocol):
    async def ingest(self, baseline: dict[str, Any]) -> None:
        """Embed and store one baseline for future peer-cohort comparisons."""
        ...

    async def check(self, baseline: dict[str, Any]) -> dict[str, Any]:
        """Anomaly verdict for this baseline against its vendor+OS peer
        cohort. Shape: {"status": "scored", "is_anomaly": bool,
        "anomaly_score": float, "peer_count": int} | {"status":
        "insufficient_peers", "peer_count": int} | {"status": "not_ingested"
        | "unavailable"}."""
        ...


class EmptyAnomalyDetectionProvider:
    """Safe default: Compliance works when Learning is unavailable or
    unconfigured."""

    async def ingest(self, baseline: dict[str, Any]) -> None:
        return None

    async def check(self, baseline: dict[str, Any]) -> dict[str, Any]:
        return {"status": "unavailable"}


class LearningAnomalyDetectionProvider:
    def __init__(self, base_url: str, *, timeout_seconds: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    async def ingest(self, baseline: dict[str, Any]) -> None:
        device = baseline.get("device") or {}
        config_sha256 = device.get("config_sha256")
        if not config_sha256:
            return
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            response = await client.post(
                f"{self.base_url}/learning/baseline-vectors",
                json={
                    "config_sha256": config_sha256,
                    "vendor": device.get("detected_vendor") or "unknown",
                    "os": device.get("detected_os"),
                    "baseline": baseline,
                },
            )
            response.raise_for_status()

    async def check(self, baseline: dict[str, Any]) -> dict[str, Any]:
        device = baseline.get("device") or {}
        config_sha256 = device.get("config_sha256")
        if not config_sha256:
            return {"status": "unavailable"}
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            response = await client.post(
                f"{self.base_url}/learning/baseline-vectors/anomaly-check",
                json={
                    "config_sha256": config_sha256,
                    "vendor": device.get("detected_vendor") or "unknown",
                    "os": device.get("detected_os"),
                },
            )
            response.raise_for_status()
            return response.json()


def build_anomaly_detection_provider() -> AnomalyDetectionProvider:
    """LEARNING_URL unset means Learning isn't configured for this
    environment (e.g. running the service standalone per the README) —
    fall back to the no-op provider."""
    base_url = os.getenv("LEARNING_URL")
    if not base_url:
        return EmptyAnomalyDetectionProvider()
    return LearningAnomalyDetectionProvider(base_url)
