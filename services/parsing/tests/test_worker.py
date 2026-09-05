import hashlib

import pytest

from app import worker
from app.models import DeviceContext


class FakeSLM:
    def __init__(self):
        self.prompts = []

    async def generate(self, prompt, config_text, schema, *, device_context):
        self.prompts.append((prompt, device_context.vendor, device_context.os, config_text))
        return {
            "schema_version": "1.0.0",
            "device": {"parsing_confidence": 0.90},
        }


class FakeRAG:
    async def retrieve(self, vendor, os_name, config_text):
        return ""


def make_job():
    return {
        "job_id": "00000000-0000-0000-0000-000000000001",
        "file_hash": hashlib.sha256(b"whole-file").hexdigest(),
        "storage_path": "raw/x.cfg",
        "original_filename": "x.cfg",
        "uploaded_by": "test",
        "uploaded_at": "2026-01-01T00:00:00+00:00",
        "chunk_count": 3,
        "chunks": [
            {"index": 0, "text": "hostname EDGE-RTR\nversion 17.9.3\nip ssh version 2"},
            {"index": 1, "text": "interface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0"},
            {"index": 2, "text": "ip access-list extended MGMT\n permit ip any any"},
        ],
    }


@pytest.mark.asyncio
async def test_vendor_context_is_detected_once_and_passed_to_all_chunks(monkeypatch):
    fake_slm = FakeSLM()
    sent = []
    monkeypatch.setattr(worker.celery_app, "send_task", lambda *args, **kwargs: sent.append((args, kwargs)))
    result = await worker._process_config(make_job(), slm_client=fake_slm, rag_provider=FakeRAG())

    assert result["status"] == "submitted"
    assert result["baseline"]["device"]["detected_vendor"] == "cisco"
    assert result["baseline"]["device"]["parsing_confidence"] > 0
    assert len(fake_slm.prompts) == 3
    assert [vendor for _, vendor, _, _ in fake_slm.prompts] == ["cisco", "cisco", "cisco"]
    assert all("Detected vendor: cisco" in prompt for prompt, *_ in fake_slm.prompts)
    assert sent[0][0][0] == "compliance.evaluate_baseline"
    payload = sent[0][1]["args"][0]
    assert set(payload) == {"audit_run_id", "framework", "baseline"}
    assert payload["audit_run_id"] == make_job()["job_id"]
    assert payload["framework"] == "CIS"
    assert payload["baseline"]["device"]["config_sha256"] == make_job()["file_hash"]


@pytest.mark.asyncio
async def test_unknown_vendor_is_never_published(monkeypatch):
    job = make_job()
    job["chunks"] = [{"index": 0, "text": "interface GigabitEthernet0/0"}]
    job["chunk_count"] = 1
    fake_slm = FakeSLM()
    sent = []
    monkeypatch.setattr(worker.celery_app, "send_task", lambda *args, **kwargs: sent.append((args, kwargs)))
    result = await worker._process_config(job, slm_client=fake_slm, rag_provider=FakeRAG())

    assert result["status"] == "human_review"
    assert result["baseline"]["device"]["detected_vendor"] == "unknown"
    assert result["baseline"]["device"]["parsing_confidence"] < worker.settings.confidence_threshold
    assert sent == []


@pytest.mark.asyncio
async def test_invalid_model_enum_enters_unknown_block_path(monkeypatch):
    class InvalidSLM(FakeSLM):
        async def generate(self, prompt, config_text, schema, *, device_context):
            return {
                "schema_version": "1.0.0",
                "device": {"parsing_confidence": 0.9},
                "crypto": {"ike_policies": [{"encryption": "AES999"}]},
            }

    job = make_job()
    sent = []
    monkeypatch.setattr(worker.celery_app, "send_task", lambda *args, **kwargs: sent.append((args, kwargs)))
    result = await worker._process_config(job, slm_client=InvalidSLM(), rag_provider=FakeRAG())
    assert result["status"] == "human_review"
    assert result["unknown_blocks"][0]["chunk_index"] == 0
    assert "AES999" in result["unknown_blocks"][0]["reason"]
    assert sent == []


def test_task_name():
    assert worker.process_config.name == "parsing.process_config"


@pytest.mark.asyncio
async def test_rag_failure_does_not_block_parsing(monkeypatch):
    class FailingRAG:
        async def retrieve(self, vendor, os_name, config_text):
            raise RuntimeError("chromadb unavailable")

    sent = []
    monkeypatch.setattr(worker.celery_app, "send_task", lambda *args, **kwargs: sent.append((args, kwargs)))
    result = await worker._process_config(
        make_job(),
        slm_client=FakeSLM(),
        rag_provider=FailingRAG(),
    )
    assert result["status"] == "submitted"
    assert sent
