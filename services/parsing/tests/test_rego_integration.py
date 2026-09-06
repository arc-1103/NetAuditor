import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from app import worker
from app.models import DeviceContext

REPO_ROOT = Path(__file__).resolve().parents[3]
POLICIES = REPO_ROOT / "services" / "compliance" / "policies"


class InsecureCiscoSLM:
    async def generate(self, prompt, config_text, schema, *, device_context):
        return {
            "schema_version": "1.0.0",
            "device": {"parsing_confidence": 0.91},
            "aaa": {"password_encryption": "DISABLED"},
            "ssh": {"enabled": True, "version": "1-2", "management_acl": None},
            "telnet": {"enabled": "ENABLED"},
            "snmp": {"enabled": True, "version": "v2c", "community_strings": ["public"]},
            "logging": {"syslog_enabled": False, "syslog_hosts": []},
            "ntp": {"enabled": True, "authentication_enabled": False},
            "crypto": {"ike_policies": [{"policy_id": 10, "encryption": "3DES"}]},
            "banners": {"login_banner_present": False},
            "services": {"http_server_enabled": "ENABLED"},
        }


class EmptyRAG:
    async def retrieve(self, vendor, os_name, config_text):
        return ""


@pytest.mark.asyncio
async def test_parsing_output_is_accepted_by_actual_cisco_rego(tmp_path, monkeypatch):
    opa = shutil.which("opa")
    if opa is None:
        pytest.skip("opa binary not available; run this test in the NetAuditor toolchain")
    policy_file = POLICIES / "cis" / "cisco_ios_level1.rego"
    if not policy_file.exists():
        pytest.skip(f"actual Rego policy not present at {policy_file}")

    job = {
        "job_id": "00000000-0000-0000-0000-000000000002",
        "file_hash": hashlib.sha256(b"insecure-cisco").hexdigest(),
        "storage_path": "raw-configs/insecure.cfg",
        "original_filename": "insecure.cfg",
        "uploaded_by": "unknown",
        "uploaded_at": "2026-01-01T00:00:00+00:00",
        "chunk_count": 1,
        "chunks": [{"index": 0, "text": "hostname EDGE-RTR\nversion 17.9.3"}],
    }
    monkeypatch.setattr(worker.celery_app, "send_task", lambda *args, **kwargs: None)
    result = await worker._process_config(
        job,
        slm_client=InsecureCiscoSLM(),
        rag_provider=EmptyRAG(),
    )
    assert result["status"] == "submitted"
    assert result["baseline"]["device"]["detected_vendor"] == "cisco"

    input_file = tmp_path / "baseline.json"
    input_file.write_text(json.dumps(result["baseline"]))
    proc = subprocess.run(
        [opa, "eval", "-d", str(POLICIES), "-i", str(input_file), "-f", "json", "data.compliance.cis"],
        capture_output=True,
        text=True,
        check=True,
    )
    body = json.loads(proc.stdout)
    result_obj = body["result"][0]["expressions"][0]["value"]
    serialized = json.dumps(result_obj)
    assert "CIS-IOS-1.1.1" in serialized
    assert "CIS-IOS-1.1.2" in serialized
