"""
Unit tests for app.queue_producer: the Celery payload must match
contracts/ingestion_job.schema.json. No real broker is touched — Celery
dispatch is monkeypatched.
"""
from unittest.mock import MagicMock

import pytest

from app import queue_producer


@pytest.fixture
def fake_celery(monkeypatch):
    fake = MagicMock()
    monkeypatch.setattr(queue_producer, "celery_app", fake)
    return fake


def test_builds_contract_shaped_payload(fake_celery):
    stored = {
        "file_hash": "a" * 64,
        "storage_path": "raw-configs/aaa.cfg",
        "original_filename": "device.cfg",
    }
    chunks = ["block one", "block two"]

    job = queue_producer.enqueue_parsing_job("job-123", stored, chunks, "user-1")

    assert job["job_id"] == "job-123"
    assert job["file_hash"] == stored["file_hash"]
    assert job["storage_path"] == stored["storage_path"]
    assert job["original_filename"] == "device.cfg"
    assert job["uploaded_by"] == "user-1"
    assert job["chunk_count"] == 2
    assert job["chunks"] == [
        {"index": 0, "text": "block one"},
        {"index": 1, "text": "block two"},
    ]
    assert "uploaded_at" in job


def test_dispatches_exactly_one_celery_task(fake_celery):
    stored = {"file_hash": "b" * 64, "storage_path": "raw-configs/bbb.cfg", "original_filename": "b.cfg"}

    job = queue_producer.enqueue_parsing_job("job-456", stored, [], "user-1")

    fake_celery.send_task.assert_called_once_with("parsing.process_config", args=[job], queue="parsing")


def test_missing_uploader_falls_back_to_unknown_not_none(fake_celery):
    stored = {"file_hash": "c" * 64, "storage_path": "raw-configs/ccc.cfg", "original_filename": None}

    job = queue_producer.enqueue_parsing_job("job-789", stored, [], None)

    assert job["uploaded_by"] == "unknown"
