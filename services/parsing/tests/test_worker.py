import hashlib
from dataclasses import replace
from unittest.mock import AsyncMock

import pytest

from app import worker
from app.models import DeviceContext, SLMResult
from app.slm_client import SLMError
from app.vendor_fingerprint import EmptyVendorFingerprintProvider, VendorGuess


class FakeVendorFingerprint:
    def __init__(self, guess=None):
        self.guess = guess
        self.calls = []

    async def identify(self, text):
        self.calls.append(text)
        return self.guess


class FakeSLM:
    def __init__(self, confidence=0.90, mean_logprob=None):
        self.prompts = []
        self.confidence = confidence
        self.mean_logprob = mean_logprob

    async def generate(self, prompt, config_text, schema, *, device_context):
        self.prompts.append((prompt, device_context.vendor, device_context.os, config_text))
        return SLMResult(
            value={
                "schema_version": "1.0.0",
                "device": {"parsing_confidence": self.confidence},
            },
            mean_logprob=self.mean_logprob,
        )

    async def reverse_translate(self, baseline_json, device_context):
        # These fixtures never populate a field outside device.* (which the
        # fidelity diff excludes anyway), so any non-empty string here
        # yields a trivial 1.0 fidelity on round trip — existing tests stay
        # unaffected by the reverse-translation gate.
        return "hostname EDGE-RTR"


class SequencedSLM:
    """Returns a different generate() response on each call, in order — for
    simulating a forward candidate that diverges from its own round-trip
    re-extraction (reverse-translation fidelity tests)."""

    def __init__(self, responses, reconstructed_cli="some cli", mean_logprob=None):
        self._responses = list(responses)
        self.reconstructed_cli = reconstructed_cli
        self.mean_logprob = mean_logprob
        self.prompts = []

    async def generate(self, prompt, config_text, schema, *, device_context):
        self.prompts.append(prompt)
        value = self._responses.pop(0)
        return SLMResult(value=value, mean_logprob=self.mean_logprob)

    async def reverse_translate(self, baseline_json, device_context):
        return self.reconstructed_cli


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
    result = await worker._process_config(
        make_job(), slm_client=fake_slm, rag_provider=FakeRAG(), vendor_fingerprint_provider=EmptyVendorFingerprintProvider()
    )

    assert result["status"] == "submitted"
    assert result["baseline"]["device"]["detected_vendor"] == "cisco"
    assert result["baseline"]["device"]["parsing_confidence"] > 0
    # 2 generate() calls per chunk: the forward extraction, and the
    # reverse-translation round-trip re-extraction (app/worker.py's
    # _check_reverse_translation_fidelity).
    assert len(fake_slm.prompts) == 6
    assert [vendor for _, vendor, _, _ in fake_slm.prompts] == ["cisco"] * 6
    assert all("Detected vendor: cisco" in prompt for prompt, *_ in fake_slm.prompts)
    assert sent[0][0][0] == "compliance.evaluate_baseline"
    payload = sent[0][1]["args"][0]
    assert set(payload) == {"audit_run_id", "framework", "baseline", "source_text"}
    assert payload["audit_run_id"] == make_job()["job_id"]
    assert payload["framework"] == "CIS"
    assert payload["baseline"]["device"]["config_sha256"] == make_job()["file_hash"]


@pytest.mark.asyncio
async def test_unrecognized_vendor_is_still_published_when_confidence_is_high(monkeypatch):
    """The core fix: an unrecognized vendor is not the same thing as an
    unparseable one. A regex fingerprint miss must not, by itself, block a
    device from reaching Compliance when the SLM's own extraction is good."""
    job = make_job()
    job["chunks"] = [{"index": 0, "text": "interface GigabitEthernet0/0"}]
    job["chunk_count"] = 1
    fake_slm = FakeSLM(confidence=0.90)
    sent = []
    monkeypatch.setattr(worker.celery_app, "send_task", lambda *args, **kwargs: sent.append((args, kwargs)))
    result = await worker._process_config(
        job,
        slm_client=fake_slm,
        rag_provider=FakeRAG(),
        vendor_fingerprint_provider=EmptyVendorFingerprintProvider(),
    )

    assert result["status"] == "submitted"
    assert result["baseline"]["device"]["detected_vendor"] == "unknown"
    assert result["baseline"]["device"]["parsing_confidence"] >= worker.settings.confidence_threshold
    assert sent[0][0][0] == "compliance.evaluate_baseline"


@pytest.mark.asyncio
async def test_low_confidence_triggers_human_review_even_for_a_known_vendor(monkeypatch):
    """Gating is confidence-only now — a recognized vendor name doesn't
    exempt a poorly-extracted device from human review."""
    job = make_job()
    fake_slm = FakeSLM(confidence=0.20)
    sent = []
    monkeypatch.setattr(worker.celery_app, "send_task", lambda *args, **kwargs: sent.append((args, kwargs)))
    mark_needs_review = AsyncMock()
    monkeypatch.setattr(worker.db, "mark_needs_review", mark_needs_review)
    result = await worker._process_config(
        job,
        slm_client=fake_slm,
        rag_provider=FakeRAG(),
        vendor_fingerprint_provider=EmptyVendorFingerprintProvider(),
    )

    assert result["status"] == "human_review"
    assert result["baseline"]["device"]["detected_vendor"] == "cisco"
    assert result["baseline"]["device"]["parsing_confidence"] < worker.settings.confidence_threshold
    assert sent == []

    mark_needs_review.assert_awaited_once()
    run_id, detail = mark_needs_review.await_args.args
    assert run_id == job["job_id"]
    assert detail["reason"] == "parsing_confidence_below_threshold"
    assert detail["detected_vendor"] == "cisco"


@pytest.mark.asyncio
async def test_invalid_model_enum_enters_unknown_block_path(monkeypatch):
    class InvalidSLM(FakeSLM):
        async def generate(self, prompt, config_text, schema, *, device_context):
            return SLMResult(
                value={
                    "schema_version": "1.0.0",
                    "device": {"parsing_confidence": 0.9},
                    "crypto": {"ike_policies": [{"encryption": "AES999"}]},
                }
            )

    job = make_job()
    sent = []
    monkeypatch.setattr(worker.celery_app, "send_task", lambda *args, **kwargs: sent.append((args, kwargs)))
    mark_needs_review = AsyncMock()
    monkeypatch.setattr(worker.db, "mark_needs_review", mark_needs_review)
    fake_fingerprint = FakeVendorFingerprint(guess=VendorGuess(vendor="juniper", os="JunOS", confidence=0.5))
    result = await worker._process_config(
        job, slm_client=InvalidSLM(), rag_provider=FakeRAG(), vendor_fingerprint_provider=fake_fingerprint
    )
    assert result["status"] == "human_review"
    assert result["unknown_blocks"][0]["chunk_index"] == 0
    assert "AES999" in result["unknown_blocks"][0]["reason"]

    # No baseline is good enough to reach Compliance, but every failed chunk
    # still needs to reach a human via the Learning lane.
    assert [call_args[0] for call_args, _ in sent] == ["learning.receive_unknown_block"] * 3
    payload = sent[0][1]["args"][0]
    assert payload["block_id"] == f"{job['job_id']}:0"
    assert payload["audit_run_id"] == job["job_id"]
    assert payload["raw_text"] == job["chunks"][0]["text"]

    # No chunk parsed at all — the run must not stall silently either.
    mark_needs_review.assert_awaited_once()
    run_id, detail = mark_needs_review.await_args.args
    assert run_id == job["job_id"]
    assert detail["reason"] == "no_chunks_parsed"
    assert detail["detected_vendor"] == "cisco"

    # The vendor is already known (cisco) — the semantic fallback is only
    # for a genuinely unknown vendor, so it must not even be called.
    assert fake_fingerprint.calls == []
    assert "semantic_vendor_guess" not in detail


@pytest.mark.asyncio
async def test_low_mean_logprob_forces_human_review_even_with_high_field_confidence(monkeypatch):
    """Active learning via token uncertainty: a chunk the model wasn't
    actually sure about must reach manual review even when its field-count
    confidence looks fine, and it must be routed through the same
    Learning-lane unknown-block path a validation failure would use."""
    job = make_job()
    job["chunks"] = [job["chunks"][0]]
    job["chunk_count"] = 1
    fake_slm = FakeSLM(confidence=0.90, mean_logprob=-0.9)
    sent = []
    monkeypatch.setattr(worker.celery_app, "send_task", lambda *args, **kwargs: sent.append((args, kwargs)))
    mark_needs_review = AsyncMock()
    monkeypatch.setattr(worker.db, "mark_needs_review", mark_needs_review)
    result = await worker._process_config(
        job,
        slm_client=fake_slm,
        rag_provider=FakeRAG(),
        vendor_fingerprint_provider=EmptyVendorFingerprintProvider(),
    )

    assert result["status"] == "human_review"
    assert result["reason"] == "No chunks could be parsed"
    assert "low_token_confidence" in result["unknown_blocks"][0]["reason"]
    assert len(sent) == 1
    assert sent[0][0][0] == "learning.receive_unknown_block"
    assert sent[0][1]["args"][0]["block_id"] == f"{job['job_id']}:0"


@pytest.mark.asyncio
async def test_missing_mean_logprob_does_not_trigger_the_uncertainty_gate(monkeypatch):
    """`None` means the backend gave no logprob signal at all, which is not
    the same thing as low confidence, and must not force human review."""
    fake_slm = FakeSLM(confidence=0.90, mean_logprob=None)
    sent = []
    monkeypatch.setattr(worker.celery_app, "send_task", lambda *args, **kwargs: sent.append((args, kwargs)))
    result = await worker._process_config(
        make_job(),
        slm_client=fake_slm,
        rag_provider=FakeRAG(),
        vendor_fingerprint_provider=EmptyVendorFingerprintProvider(),
    )
    assert result["status"] == "submitted"


def test_task_name():
    assert worker.process_config.name == "parsing.process_config"


@pytest.mark.asyncio
async def test_low_reverse_translation_fidelity_forces_human_review(monkeypatch):
    """Multi-agent reverse translation: Agent A's candidate is diffed
    against a fresh forward extraction of Agent B's CLI reconstruction. A
    forward candidate whose fields vanish on round trip is evidence of
    hallucinated/dropped data, independent of the logprob and confidence
    gates, and must reach human review the same way."""
    job = make_job()
    job["chunks"] = [job["chunks"][0]]
    job["chunk_count"] = 1
    fake_slm = SequencedSLM(
        responses=[
            {
                "schema_version": "1.0.0",
                "device": {"parsing_confidence": 0.9},
                "ssh": {"enabled": True, "version": "2"},
                "telnet": {"enabled": "DISABLED"},
            },
            # Round trip on Agent B's reconstruction recovers nothing.
            {"schema_version": "1.0.0", "device": {"parsing_confidence": 0.9}},
        ]
    )
    sent = []
    monkeypatch.setattr(worker.celery_app, "send_task", lambda *a, **k: sent.append((a, k)))
    mark_needs_review = AsyncMock()
    monkeypatch.setattr(worker.db, "mark_needs_review", mark_needs_review)

    result = await worker._process_config(
        job, slm_client=fake_slm, rag_provider=FakeRAG(), vendor_fingerprint_provider=EmptyVendorFingerprintProvider()
    )

    assert result["status"] == "human_review"
    assert "reverse_translation_fidelity_below_threshold" in result["unknown_blocks"][0]["reason"]


@pytest.mark.asyncio
async def test_high_reverse_translation_fidelity_does_not_block_parsing(monkeypatch):
    job = make_job()
    job["chunks"] = [job["chunks"][0]]
    job["chunk_count"] = 1
    same_value = {
        "schema_version": "1.0.0",
        "device": {"parsing_confidence": 0.9},
        "ssh": {"enabled": True, "version": "2"},
    }
    fake_slm = SequencedSLM(responses=[dict(same_value), dict(same_value)])
    sent = []
    monkeypatch.setattr(worker.celery_app, "send_task", lambda *a, **k: sent.append((a, k)))

    result = await worker._process_config(
        job, slm_client=fake_slm, rag_provider=FakeRAG(), vendor_fingerprint_provider=EmptyVendorFingerprintProvider()
    )

    assert result["status"] == "submitted"


@pytest.mark.asyncio
async def test_reverse_translation_failure_degrades_gracefully(monkeypatch):
    """An Ollama hiccup on Agent B is not evidence Agent A's own extraction
    was wrong — it must not block an otherwise good chunk."""

    class FailingReverseSLM(FakeSLM):
        async def reverse_translate(self, baseline_json, device_context):
            raise SLMError("ollama unavailable for reverse translation")

    sent = []
    monkeypatch.setattr(worker.celery_app, "send_task", lambda *a, **k: sent.append((a, k)))

    result = await worker._process_config(
        make_job(),
        slm_client=FailingReverseSLM(confidence=0.9),
        rag_provider=FakeRAG(),
        vendor_fingerprint_provider=EmptyVendorFingerprintProvider(),
    )

    assert result["status"] == "submitted"


@pytest.mark.asyncio
async def test_disabling_reverse_translation_skips_the_check_entirely(monkeypatch):
    monkeypatch.setattr(worker, "settings", replace(worker.settings, enable_reverse_translation=False))
    monkeypatch.setattr(worker.celery_app, "send_task", lambda *a, **k: None)
    calls = []

    class SpySLM(FakeSLM):
        async def reverse_translate(self, baseline_json, device_context):
            calls.append(1)
            return "should not be called"

    result = await worker._process_config(
        make_job(),
        slm_client=SpySLM(confidence=0.9),
        rag_provider=FakeRAG(),
        vendor_fingerprint_provider=EmptyVendorFingerprintProvider(),
    )

    assert result["status"] == "submitted"
    assert calls == []


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
        vendor_fingerprint_provider=EmptyVendorFingerprintProvider(),
    )
    assert result["status"] == "submitted"
    assert sent
