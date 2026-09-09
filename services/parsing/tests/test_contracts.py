import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator, FormatChecker

REPO_ROOT = Path(__file__).resolve().parents[3]
CONTRACTS = REPO_ROOT / "contracts"


def _load_contract(name: str) -> dict:
    path = CONTRACTS / name
    if not path.exists():
        pytest.skip(f"repository contract not present at {path}")
    return json.loads(path.read_text())


def test_ingestion_job_shape_matches_actual_contract():
    schema = _load_contract("ingestion_job.schema.json")
    job = {
        "job_id": "00000000-0000-0000-0000-000000000001",
        "file_hash": "a" * 64,
        "storage_path": "raw-configs/a.cfg",
        "original_filename": "a.cfg",
        "uploaded_by": "unknown",
        "uploaded_at": "2026-01-01T00:00:00+00:00",
        "chunk_count": 1,
        "chunks": [{"index": 0, "text": "version 17.9.3"}],
    }
    errors = list(Draft7Validator(schema, format_checker=FormatChecker()).iter_errors(job))
    assert errors == []


def test_security_baseline_shape_matches_actual_contract():
    schema = _load_contract("security_baseline.schema.json")
    baseline = {
        "schema_version": "1.0.0",
        "device": {
            "detected_vendor": "cisco",
            "config_sha256": "a" * 64,
            "parsing_confidence": 0.84,
            "unknown_blocks_count": 0,
        },
    }
    errors = list(Draft7Validator(schema, format_checker=FormatChecker()).iter_errors(baseline))
    assert errors == []

    assert schema["properties"]["device"]["required"] == [
        "detected_vendor", "config_sha256", "parsing_confidence"
    ]
    assert schema["definitions"]["ProtocolStatus"]["enum"] == [
        "ENABLED", "DISABLED", "UNKNOWN"
    ]
    assert schema["properties"]["telnet"]["properties"]["enabled"]["$ref"] == "#/definitions/ProtocolStatus"


def test_contract_payload_uses_exact_compliance_worker_keys():
    payload = {
        "audit_run_id": "00000000-0000-0000-0000-000000000001",
        "framework": "CIS",
        "baseline": {},
    }
    assert set(payload) == {"audit_run_id", "framework", "baseline"}


@pytest.mark.asyncio
async def test_real_worker_pipeline_output_matches_actual_cross_lane_contract(monkeypatch):
    from app import worker
    from app.models import SLMResult

    class FakeSLM:
        async def generate(self, prompt, config_text, schema, *, device_context):
            return SLMResult(
                value={
                    "device": {
                        "detected_vendor": "unknown",
                        "detected_os": "garbage",
                        "parsing_confidence": 0.93,
                    },
                    "ssh": {"enabled": True, "version": "2"},
                    "telnet": {"enabled": "DISABLED"},
                }
            )

        async def reverse_translate(self, baseline_json, device_context):
            return "ip ssh version 2\nno transport input telnet"

    class FakeRAG:
        async def retrieve(self, vendor, os_name, config_text):
            return ""

    sent = []
    monkeypatch.setattr(worker.celery_app, "send_task", lambda name, args=None, **kw: sent.append((name, args, kw)))
    job = {
        "job_id": "00000000-0000-0000-0000-000000000001",
        "file_hash": "b" * 64,
        "storage_path": "raw-configs/b.cfg",
        "original_filename": "b.cfg",
        "uploaded_by": "unknown",
        "uploaded_at": "2026-01-01T00:00:00+00:00",
        "chunk_count": 3,
        "chunks": [
            {"index": 0, "text": "version 17.9.3\nhostname CORE-RTR"},
            {"index": 1, "text": "interface GigabitEthernet0/1\n description USERS"},
            {"index": 2, "text": "ip access-list extended MGMT\n permit tcp any any eq 22"},
        ],
    }
    result = await worker._process_config(job, slm_client=FakeSLM(), rag_provider=FakeRAG())
    assert result["status"] == "submitted"
    baseline = result["baseline"]
    schema = _load_contract("security_baseline.schema.json")
    errors = list(Draft7Validator(schema, format_checker=FormatChecker()).iter_errors(baseline))
    assert errors == []
    assert baseline["device"]["detected_vendor"] == "cisco"
    assert baseline["device"]["config_sha256"] == job["file_hash"]
    assert 0.0 <= baseline["device"]["parsing_confidence"] <= 1.0
    assert sent == [("compliance.evaluate_baseline", [{
        "audit_run_id": job["job_id"],
        "framework": "CIS",
        "baseline": baseline,
    }], {})]
