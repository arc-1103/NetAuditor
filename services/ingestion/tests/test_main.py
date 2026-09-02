"""
Endpoint tests for POST /upload's orchestration (validate -> record
AuditRun -> chunk -> enqueue). uploader/db/queue calls are mocked at the
app.main boundary so no MinIO/Postgres/Redis is required — those pieces
each have their own dedicated unit tests.
"""
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_health(client):
    resp = client.get("/health")

    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "service": "ingestion"}


def test_upload_happy_path_returns_queued_job(client, monkeypatch):
    stored = {
        "file_hash": "c" * 64,
        "storage_path": "raw-configs/ccc.cfg",
        "original_filename": "device.cfg",
        "raw_text": "hostname r1\n",
    }
    create_audit_run_mock = AsyncMock()
    monkeypatch.setattr("app.main.validate_and_store", AsyncMock(return_value=stored))
    monkeypatch.setattr("app.main.create_audit_run", create_audit_run_mock)
    monkeypatch.setattr(
        "app.main.enqueue_parsing_job",
        lambda job_id, s, chunks, uploaded_by: {"job_id": job_id},
    )

    resp = client.post(
        "/upload",
        files={"file": ("device.cfg", b"hostname r1\n", "text/plain")},
        headers={"X-User-Id": "11111111-1111-1111-1111-111111111111"},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "queued"
    assert "job_id" in body

    create_audit_run_mock.assert_called_once()
    run_id, stored_arg, uploaded_by = create_audit_run_mock.call_args.args
    assert stored_arg == stored
    assert uploaded_by == "11111111-1111-1111-1111-111111111111"
    assert run_id == body["job_id"]


def test_upload_rejects_invalid_file_with_400(client, monkeypatch):
    monkeypatch.setattr(
        "app.main.validate_and_store",
        AsyncMock(side_effect=ValueError("Extension .exe not allowed")),
    )

    resp = client.post("/upload", files={"file": ("device.exe", b"bad", "application/octet-stream")})

    assert resp.status_code == 400
    assert "not allowed" in resp.json()["detail"]


def test_upload_without_user_header_stores_no_attribution(client, monkeypatch):
    stored = {
        "file_hash": "d" * 64,
        "storage_path": "raw-configs/ddd.cfg",
        "original_filename": "device.cfg",
        "raw_text": "hostname r2\n",
    }
    create_audit_run_mock = AsyncMock()
    monkeypatch.setattr("app.main.validate_and_store", AsyncMock(return_value=stored))
    monkeypatch.setattr("app.main.create_audit_run", create_audit_run_mock)
    monkeypatch.setattr(
        "app.main.enqueue_parsing_job",
        lambda job_id, s, chunks, uploaded_by: {"job_id": job_id},
    )

    resp = client.post("/upload", files={"file": ("device.cfg", b"hostname r2\n", "text/plain")})

    assert resp.status_code == 200
    _, _, uploaded_by = create_audit_run_mock.call_args.args
    assert uploaded_by is None


def test_upload_with_malformed_user_header_degrades_gracefully(client, monkeypatch):
    stored = {
        "file_hash": "d" * 64,
        "storage_path": "raw-configs/ddd.cfg",
        "original_filename": "device.cfg",
        "raw_text": "hostname r2\n",
    }
    create_audit_run_mock = AsyncMock()
    monkeypatch.setattr("app.main.validate_and_store", AsyncMock(return_value=stored))
    monkeypatch.setattr("app.main.create_audit_run", create_audit_run_mock)
    monkeypatch.setattr(
        "app.main.enqueue_parsing_job",
        lambda job_id, s, chunks, uploaded_by: {"job_id": job_id},
    )

    resp = client.post(
        "/upload",
        files={"file": ("device.cfg", b"hostname r2\n", "text/plain")},
        headers={"X-User-Id": "not-a-uuid"},
    )

    assert resp.status_code == 200
    _, _, uploaded_by = create_audit_run_mock.call_args.args
    assert uploaded_by is None
