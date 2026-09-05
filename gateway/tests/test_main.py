"""
Endpoint tests for the gateway route table (contracts/api_gateway_routes.md).
Downstream services (ingestion/compliance/learning/remediation/reporting)
don't exist yet, so the httpx boundary is faked — these tests verify the
gateway's own auth gating and request/response shaping, not what a real
downstream service would return.
"""
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.auth import get_current_user
from app.db import get_session

FAKE_USER = {
    "sub": "11111111-1111-1111-1111-111111111111",
    "email": "admin@netaudit.local",
    "role": "admin",
}


class FakeResponse:
    def __init__(self, status_code=200, json_data=None, text_body=""):
        self.status_code = status_code
        self._json = {} if json_data is None else json_data
        self.text = text_body

    def json(self):
        return self._json


class FakeAsyncClient:
    """Stands in for httpx.AsyncClient — records every call it's asked to
    make and always answers with the response it was constructed with."""

    last_instance: "FakeAsyncClient | None" = None

    def __init__(self, response: FakeResponse):
        self.response = response
        self.calls = []
        FakeAsyncClient.last_instance = self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False

    async def _record(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, "kwargs": kwargs})
        return self.response

    async def get(self, url, **kwargs):
        return await self._record("GET", url, **kwargs)

    async def post(self, url, **kwargs):
        return await self._record("POST", url, **kwargs)


@pytest.fixture
def client():
    app.dependency_overrides[get_current_user] = lambda: FAKE_USER
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def fake_proxy(monkeypatch):
    def _install(response: FakeResponse):
        monkeypatch.setattr("app.main.httpx.AsyncClient", lambda *a, **k: FakeAsyncClient(response))

    return _install


def last_proxy_call() -> dict:
    """The most recent call recorded by the FakeAsyncClient installed via
    `fake_proxy` — only valid after the route under test has actually
    reached the httpx boundary."""
    assert FakeAsyncClient.last_instance is not None, "no proxy call was made"
    return FakeAsyncClient.last_instance.calls[0]


def test_login_returns_token_on_valid_credentials(monkeypatch):
    monkeypatch.setattr(
        "app.main.authenticate_user",
        AsyncMock(return_value={"id": "u-1", "email": "admin@netaudit.local", "role": "admin"}),
    )
    monkeypatch.setattr("app.main.issue_token", lambda user: "fake-jwt-token")

    # Not a monkeypatch.setattr target (it's a dict mutation on the shared
    # `app` singleton, not an attribute), so it needs its own try/finally
    # to guarantee cleanup even if the request below raises.
    app.dependency_overrides[get_session] = lambda: None
    try:
        resp = TestClient(app).post(
            "/api/login", json={"email": "admin@netaudit.local", "password": "changeme"}
        )
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 200
    body = resp.json()
    assert body["access_token"] == "fake-jwt-token"
    assert body["token_type"] == "bearer"
    assert body["user"]["email"] == "admin@netaudit.local"


@pytest.mark.parametrize(
    "method,path,kwargs",
    [
        ("get", "/api/audit-runs/run-1", {}),
        ("post", "/api/reports/generate", {"json": {"audit_run_id": "run-1"}}),
        ("get", "/api/learning/queue", {}),
        (
            "post",
            "/api/learning/map",
            {"json": {"block_id": "b1", "cli_pattern": "x", "field": "y", "value": "z"}},
        ),
        ("post", "/api/remediation/AC-2/approve", {"json": {"approved": True}}),
    ],
)
def test_protected_routes_require_a_bearer_token(method, path, kwargs):
    resp = getattr(TestClient(app), method)(path, **kwargs)

    assert resp.status_code == 401


def test_upload_proxies_to_ingestion_with_user_attribution(client, fake_proxy):
    fake_proxy(FakeResponse(200, {"job_id": "job-1", "status": "queued"}))

    resp = client.post("/api/upload", files={"file": ("device.cfg", b"hostname r1\n", "text/plain")})

    assert resp.status_code == 200
    assert resp.json() == {"job_id": "job-1", "status": "queued"}
    call = last_proxy_call()
    assert call["kwargs"]["headers"]["X-User-Id"] == FAKE_USER["sub"]


def test_get_audit_run_proxies_to_compliance(client, fake_proxy):
    fake_proxy(FakeResponse(200, {"id": "run-1", "status": "INGESTED", "findings": []}))

    resp = client.get("/api/audit-runs/run-1")

    assert resp.status_code == 200
    assert resp.json()["id"] == "run-1"
    call = last_proxy_call()
    assert call["url"].endswith("/audit-runs/run-1")


def test_generate_report_proxies_to_reporting(client, fake_proxy):
    fake_proxy(FakeResponse(200, {"download_url": "https://example.local/report.pdf"}))

    resp = client.post("/api/reports/generate", json={"audit_run_id": "run-1"})

    assert resp.status_code == 200
    assert "download_url" in resp.json()
    call = last_proxy_call()
    assert call["kwargs"]["json"] == {"audit_run_id": "run-1"}
    assert call["url"].endswith("/reports/generate")


def test_generate_report_rejects_missing_audit_run_id(client, fake_proxy):
    fake_proxy(FakeResponse(200, {}))

    resp = client.post("/api/reports/generate", json={})

    assert resp.status_code == 422


def test_generate_report_propagates_downstream_error(client, fake_proxy):
    fake_proxy(FakeResponse(502, text_body="reporting service unavailable"))

    resp = client.post("/api/reports/generate", json={"audit_run_id": "run-1"})

    assert resp.status_code == 502


def test_get_learning_queue_proxies_to_learning(client, fake_proxy):
    fake_proxy(FakeResponse(200, [{"block_id": "b1", "raw_text": "crypto isakmp policy 10"}]))

    resp = client.get("/api/learning/queue")

    assert resp.status_code == 200
    assert resp.json()[0]["block_id"] == "b1"
    call = last_proxy_call()
    assert call["url"].endswith("/learning/queue")


def test_submit_learning_map_proxies_with_user_attribution(client, fake_proxy):
    fake_proxy(FakeResponse(200, {"confirmed": True}))
    body = {
        "block_id": "b1",
        "cli_pattern": "crypto isakmp policy 10 / hash sha256",
        "field": "crypto.ike.hash_algorithm",
        "value": "SHA256",
    }

    resp = client.post("/api/learning/map", json=body)

    assert resp.status_code == 200
    call = last_proxy_call()
    assert call["kwargs"]["json"] == body
    assert call["kwargs"]["headers"]["X-User-Id"] == FAKE_USER["sub"]


def test_submit_learning_map_rejects_incomplete_body(client, fake_proxy):
    fake_proxy(FakeResponse(200, {}))

    resp = client.post("/api/learning/map", json={"block_id": "b1"})

    assert resp.status_code == 422


def test_approve_remediation_proxies_control_id_in_path(client, fake_proxy):
    fake_proxy(FakeResponse(200, {"control_id": "AC-2", "approved": True}))

    resp = client.post("/api/remediation/AC-2/approve", json={"approved": True, "comment": "looks safe"})

    assert resp.status_code == 200
    call = last_proxy_call()
    assert call["url"].endswith("/remediation/AC-2/approve")
    assert call["kwargs"]["json"] == {"approved": True, "comment": "looks safe"}


def test_generate_all_remediations_for_run(client, fake_proxy):
    fake_proxy(FakeResponse(200, {"audit_run_id": "run-1", "generated": 3}))

    resp = client.post("/api/remediation/audit-runs/run-1/generate")

    assert resp.status_code == 200
    assert resp.json()["generated"] == 3
    assert last_proxy_call()["url"].endswith("/remediation/audit-runs/run-1/generate")


def test_list_remediations_for_run(client, fake_proxy):
    fake_proxy(FakeResponse(200, {"audit_run_id": "run-1", "remediations": []}))

    resp = client.get("/api/remediation/audit-runs/run-1")

    assert resp.status_code == 200
    assert resp.json()["remediations"] == []
