"""
Unit tests for app.anomaly_client against a fake httpx client — mirrors the
approach services/parsing/tests/test_slm.py uses for Ollama and
graph_client's own tests use for Neo4j.
"""

import httpx

from app.anomaly_client import (
    EmptyAnomalyDetectionProvider,
    LearningAnomalyDetectionProvider,
    build_anomaly_detection_provider,
)

BASELINE = {
    "device": {
        "config_sha256": "a" * 64,
        "detected_vendor": "cisco",
        "detected_os": "IOS-XE",
    },
    "ssh": {"enabled": True, "version": "2"},
}


# ── EmptyAnomalyDetectionProvider ────────────────────────────────────
async def test_empty_provider_ingest_is_a_noop():
    assert await EmptyAnomalyDetectionProvider().ingest(BASELINE) is None


async def test_empty_provider_check_reports_unavailable():
    assert await EmptyAnomalyDetectionProvider().check(BASELINE) == {"status": "unavailable"}


# ── LearningAnomalyDetectionProvider ─────────────────────────────────
def _fake_client(monkeypatch, calls, response_body=None):
    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return response_body or {}

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, url, json):
            calls.append((url, json))
            return FakeResponse()

    monkeypatch.setattr("app.anomaly_client.httpx.AsyncClient", FakeClient)


async def test_ingest_posts_the_flattened_request_to_learning(monkeypatch):
    calls = []
    _fake_client(monkeypatch, calls)
    provider = LearningAnomalyDetectionProvider("http://learning:8003")

    await provider.ingest(BASELINE)

    assert calls == [
        (
            "http://learning:8003/learning/baseline-vectors",
            {
                "config_sha256": "a" * 64,
                "vendor": "cisco",
                "os": "IOS-XE",
                "baseline": BASELINE,
            },
        )
    ]


async def test_ingest_does_nothing_without_a_config_sha256(monkeypatch):
    calls = []
    _fake_client(monkeypatch, calls)
    provider = LearningAnomalyDetectionProvider("http://learning:8003")

    await provider.ingest({"device": {}})

    assert calls == []


async def test_check_posts_and_returns_the_learning_response(monkeypatch):
    calls = []
    _fake_client(
        monkeypatch, calls,
        response_body={"status": "scored", "is_anomaly": True, "anomaly_score": -0.2, "peer_count": 8},
    )
    provider = LearningAnomalyDetectionProvider("http://learning:8003")

    result = await provider.check(BASELINE)

    assert result == {"status": "scored", "is_anomaly": True, "anomaly_score": -0.2, "peer_count": 8}
    assert calls == [
        (
            "http://learning:8003/learning/baseline-vectors/anomaly-check",
            {"config_sha256": "a" * 64, "vendor": "cisco", "os": "IOS-XE"},
        )
    ]


async def test_check_returns_unavailable_without_a_config_sha256(monkeypatch):
    calls = []
    _fake_client(monkeypatch, calls)
    provider = LearningAnomalyDetectionProvider("http://learning:8003")

    result = await provider.check({"device": {}})

    assert result == {"status": "unavailable"}
    assert calls == []


async def test_check_raises_on_a_learning_outage_so_the_caller_can_degrade(monkeypatch):
    class FailingClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, *args, **kwargs):
            raise httpx.ConnectError("learning unavailable")

    monkeypatch.setattr("app.anomaly_client.httpx.AsyncClient", FailingClient)
    provider = LearningAnomalyDetectionProvider("http://learning:8003")

    try:
        await provider.check(BASELINE)
        assert False, "expected httpx.ConnectError to propagate"
    except httpx.ConnectError:
        pass


# ── build_anomaly_detection_provider ─────────────────────────────────
def test_build_returns_empty_provider_when_learning_url_unset(monkeypatch):
    monkeypatch.delenv("LEARNING_URL", raising=False)

    assert isinstance(build_anomaly_detection_provider(), EmptyAnomalyDetectionProvider)


def test_build_returns_learning_provider_when_configured(monkeypatch):
    monkeypatch.setenv("LEARNING_URL", "http://learning:8003")

    provider = build_anomaly_detection_provider()

    assert isinstance(provider, LearningAnomalyDetectionProvider)
    assert provider.base_url == "http://learning:8003"
