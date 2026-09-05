from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime
from typing import Any
from uuid import UUID

from celery import Celery

from schema.security_baseline import SecurityBaseline

from .config import settings
from .grammar_constraints import GrammarConstraints
from .merge import merge_baselines
from .models import DeviceContext, UnknownBlock
from .normalizer import normalize_candidate
from .prompts import build_prompt
from .rag import EmptyRAGContextProvider, RAGContextProvider
from .schema_validator import BaselineValidator
from .slm_client import OllamaSLMClient, SLMError
from .vendor_detector import SUPPORTED_VENDORS, detect_job_context

logger = logging.getLogger(__name__)

celery_app = Celery("parsing", broker=settings.celery_broker_url)

_slm = OllamaSLMClient(
    settings.ollama_host,
    settings.ollama_model,
    timeout_seconds=settings.ollama_timeout_seconds,
    mock=settings.use_mock_slm,
)
_validator = BaselineValidator()
_grammar = GrammarConstraints(settings.grammar_engine)
_rag: RAGContextProvider = EmptyRAGContextProvider()


class IngestionPayloadError(ValueError):
    pass


def validate_ingestion_job(job: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(job, dict):
        raise IngestionPayloadError("ingestion job must be an object")

    required = {
        "job_id", "file_hash", "storage_path", "original_filename",
        "uploaded_by", "uploaded_at", "chunk_count", "chunks",
    }
    missing = sorted(required - job.keys())
    if missing:
        raise IngestionPayloadError(f"missing ingestion fields: {missing}")

    try:
        UUID(str(job["job_id"]))
    except (ValueError, TypeError, AttributeError) as exc:
        raise IngestionPayloadError("job_id must be a UUID") from exc

    if not isinstance(job["file_hash"], str) or not re.fullmatch(r"[a-f0-9]{64}", job["file_hash"]):
        raise IngestionPayloadError("file_hash must be a lowercase SHA-256")

    if not isinstance(job["storage_path"], str):
        raise IngestionPayloadError("storage_path must be a string")
    if job["original_filename"] is not None and not isinstance(job["original_filename"], str):
        raise IngestionPayloadError("original_filename must be string or null")
    if not isinstance(job["uploaded_by"], str):
        raise IngestionPayloadError("uploaded_by must be a string")
    if not isinstance(job["uploaded_at"], str):
        raise IngestionPayloadError("uploaded_at must be an ISO timestamp")
    try:
        datetime.fromisoformat(job["uploaded_at"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise IngestionPayloadError("uploaded_at must be an ISO date-time") from exc

    if not isinstance(job["chunk_count"], int) or job["chunk_count"] < 0:
        raise IngestionPayloadError("chunk_count must be a non-negative integer")
    if not isinstance(job["chunks"], list):
        raise IngestionPayloadError("chunks must be a list")
    if job["chunk_count"] != len(job["chunks"]):
        raise IngestionPayloadError("chunk_count does not match chunks length")

    indices = []
    for chunk in job["chunks"]:
        if not isinstance(chunk, dict) or not isinstance(chunk.get("index"), int) or chunk["index"] < 0:
            raise IngestionPayloadError("each chunk requires a non-negative integer index")
        if not isinstance(chunk.get("text"), str):
            raise IngestionPayloadError("each chunk requires string text")
        indices.append(chunk["index"])
    if indices != list(range(len(indices))):
        raise IngestionPayloadError("chunks must contain unique contiguous 0-based indices")

    return job


async def _parse_chunk(
    chunk: dict[str, Any],
    file_hash: str,
    device_context: DeviceContext,
    *,
    slm_client: OllamaSLMClient | None = None,
    rag_provider: RAGContextProvider | None = None,
) -> tuple[SecurityBaseline | None, UnknownBlock | None]:
    text = chunk["text"]
    slm = slm_client or _slm
    rag = rag_provider or _rag

    try:
        try:
            rag_context = await rag.retrieve(device_context.vendor, device_context.os, text)
        except Exception as exc:
            # Learning/RAG is optional. A ChromaDB/provider outage must not
            # turn an otherwise parseable device into a failed Parsing job.
            logger.warning("RAG enrichment unavailable for chunk %s: %s", chunk["index"], exc)
            rag_context = ""

        prompt = build_prompt(
            text,
            device_context.vendor,
            device_context.os,
            rag_context,
        )
        candidate = await slm.generate(
            prompt,
            text,
            _grammar.json_schema(),
            device_context=device_context,
        )
        raw_candidate = candidate
        candidate = normalize_candidate(candidate)

        device = candidate["device"]
        model_vendor = device.get("detected_vendor")
        if model_vendor not in {None, "", "unknown", device_context.vendor}:
            logger.warning(
                "Ignoring contradictory chunk vendor %r; job vendor is %s",
                model_vendor,
                device_context.vendor,
            )
        candidate["device"] = {
            **device,
            # Device identity is established by the job-level detector; a
            # chunk-level model response cannot replace it.
            "detected_vendor": device_context.vendor,
            "detected_os": device_context.os,
            "detected_os_version": device_context.os_version,
            "detected_hardware_model": device_context.hardware_model,
            # Source-of-truth comes from Ingestion, never from SLM output.
            "config_sha256": file_hash,
            "parsing_confidence": float(device.get("parsing_confidence", 0.0)),
        }

        baseline = SecurityBaseline.model_validate(candidate)
        return baseline, None

    except (SLMError, ValueError, TypeError) as exc:
        return None, UnknownBlock(
            chunk_index=chunk["index"],
            text=text,
            reason=str(exc),
            candidate=raw_candidate if "raw_candidate" in locals() else None,
        )


@celery_app.task(name="parsing.process_config")
def process_config(job: dict[str, Any]) -> dict[str, Any]:
    """Celery entrypoint for `parsing.process_config`."""
    return asyncio.run(_process_config(job))


async def _process_config(
    job: dict[str, Any],
    *,
    slm_client: OllamaSLMClient | None = None,
    rag_provider: RAGContextProvider | None = None,
) -> dict[str, Any]:
    validate_ingestion_job(job)

    device_context = detect_job_context(job["chunks"])
    baselines: list[SecurityBaseline] = []
    unknown_blocks: list[UnknownBlock] = []
    chunk_confidences: list[float] = []

    for chunk in sorted(job["chunks"], key=lambda item: item["index"]):
        baseline, unknown = await _parse_chunk(
            chunk,
            job["file_hash"],
            device_context,
            slm_client=slm_client,
            rag_provider=rag_provider,
        )
        if baseline is not None:
            baselines.append(baseline)
            chunk_confidences.append(float(baseline.device.parsing_confidence))
        if unknown is not None:
            unknown_blocks.append(unknown)

    if not baselines:
        return {
            "status": "human_review",
            "audit_run_id": job["job_id"],
            "reason": "No chunks could be parsed",
            "device_context": _context_to_dict(device_context),
            "unknown_blocks": [_unknown_to_dict(x) for x in unknown_blocks],
        }

    merged, conflicts = merge_baselines(baselines, device_context=device_context)
    merged.device.config_sha256 = job["file_hash"]
    merged.device.unknown_blocks_count += len(unknown_blocks)

    # Device-level confidence: vendor confidence and successful SLM extraction
    # quality are relevant; lack of a fingerprint inside a chunk is not.
    slm_confidence = sum(chunk_confidences) / len(chunk_confidences)
    confidence = min(device_context.confidence, slm_confidence)

    # Validation/parse failures reduce coverage, but do not collapse confidence
    # to zero. The published baseline is still gated below by both threshold and
    # vendor support.
    if job["chunks"] and unknown_blocks:
        failure_ratio = len(unknown_blocks) / len(job["chunks"])
        confidence *= max(0.0, 1.0 - 0.50 * failure_ratio)

    if conflicts:
        confidence = max(0.0, confidence - 0.05 * len(conflicts))

    merged.device.parsing_confidence = min(1.0, max(0.0, confidence))
    baseline_json = merged.model_dump(mode="json")

    publishable_vendor = device_context.vendor in SUPPORTED_VENDORS
    above_threshold = merged.device.parsing_confidence >= settings.confidence_threshold

    if not publishable_vendor or not above_threshold:
        return {
            "status": "human_review",
            "audit_run_id": job["job_id"],
            "baseline": baseline_json,
            "reason": (
                "unknown_or_unsupported_vendor" if not publishable_vendor
                else "parsing_confidence_below_threshold"
            ),
            "unknown_blocks": [_unknown_to_dict(x) for x in unknown_blocks],
            "conflicts": conflicts,
        }

    compliance_payload = {
        "audit_run_id": job["job_id"],
        "framework": "CIS",
        "baseline": baseline_json,
    }

    # Cross-lane communication remains Celery-only.
    celery_app.send_task("compliance.evaluate_baseline", args=[compliance_payload])

    return {
        "status": "submitted",
        "audit_run_id": job["job_id"],
        "framework": "CIS",
        "baseline": baseline_json,
        "unknown_blocks": [_unknown_to_dict(x) for x in unknown_blocks],
        "conflicts": conflicts,
    }


def _context_to_dict(context: DeviceContext) -> dict[str, Any]:
    return {
        "vendor": context.vendor,
        "os": context.os,
        "os_version": context.os_version,
        "raw_hostname": context.raw_hostname,
        "hardware_model": context.hardware_model,
        "confidence": context.confidence,
        "evidence": list(context.evidence),
    }


def _unknown_to_dict(block: UnknownBlock) -> dict[str, Any]:
    return {
        "chunk_index": block.chunk_index,
        "text": block.text,
        "reason": block.reason,
        "fields": block.fields,
        "candidate": block.candidate,
    }


if __name__ == "__main__":
    celery_app.worker_main(["worker", "--loglevel=info", "--concurrency=2"])
