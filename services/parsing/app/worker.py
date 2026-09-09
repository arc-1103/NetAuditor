from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime
from typing import Any
from uuid import UUID

from celery import Celery

from schema.security_baseline import SecurityBaseline

from . import db
from .config import settings
from .grammar_constraints import GrammarConstraints
from .merge import merge_baselines
from .models import DeviceContext, UnknownBlock
from .normalizer import normalize_candidate
from .parse_cache import ParseCacheProvider, build_parse_cache_provider
from .prompts import build_prompt
from .rag import LearningRAGContextProvider, RAGContextProvider
from .reverse_translation import compute_fidelity
from .schema_validator import BaselineValidator
from .slm_client import OllamaSLMClient, SLMError
from .vendor_detector import detect_job_context
from .vendor_fingerprint import LearningVendorFingerprintProvider, VendorFingerprintProvider

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
_rag: RAGContextProvider = LearningRAGContextProvider(
    settings.learning_url,
    correct_max_distance=settings.rag_correct_max_distance,
    ambiguous_max_distance=settings.rag_ambiguous_max_distance,
)
_vendor_fingerprint: VendorFingerprintProvider = LearningVendorFingerprintProvider(settings.learning_url)
_parse_cache: ParseCacheProvider = build_parse_cache_provider(
    enabled=settings.enable_parse_cache,
    redis_url=settings.parse_cache_redis_url,
)


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


async def _check_reverse_translation_fidelity(
    candidate: dict[str, Any],
    device_context: DeviceContext,
    *,
    slm: OllamaSLMClient,
    rag_context: str,
) -> float | None:
    """Agent B: reconstruct CLI from only the normalized JSON, then re-run
    forward extraction on that reconstruction and diff against the original
    candidate (reverse_translation.compute_fidelity).

    Returns None — "no signal", not "failed" — when the SLM call itself
    errors or produces nothing to compare. An Ollama hiccup on this
    second-order check is not evidence the *original* extraction was wrong,
    so it must not be treated as a fidelity failure; this mirrors how a
    missing mean_logprob is never treated as low confidence.
    """
    try:
        reconstructed_cli = await slm.reverse_translate(candidate, device_context)
        if not reconstructed_cli.strip():
            return None
        roundtrip_prompt = build_prompt(reconstructed_cli, device_context.vendor, device_context.os, rag_context)
        roundtrip_result = await slm.generate(
            roundtrip_prompt, reconstructed_cli, _grammar.json_schema(), device_context=device_context
        )
        roundtrip_candidate = normalize_candidate(roundtrip_result.value)
    except (SLMError, ValueError, TypeError) as exc:
        logger.warning("Reverse-translation fidelity check unavailable: %s", exc)
        return None
    return compute_fidelity(candidate, roundtrip_candidate)


async def _parse_chunk(
    chunk: dict[str, Any],
    file_hash: str,
    device_context: DeviceContext,
    *,
    slm_client: OllamaSLMClient | None = None,
    rag_provider: RAGContextProvider | None = None,
    parse_cache: ParseCacheProvider | None = None,
) -> tuple[SecurityBaseline | None, UnknownBlock | None]:
    text = chunk["text"]
    slm = slm_client or _slm
    rag = rag_provider or _rag
    cache = parse_cache or _parse_cache

    try:
        cached_candidate = await cache.get(device_context.vendor, device_context.os, text)
        if cached_candidate is not None:
            # A cache hit means this exact chunk (same vendor/os, identical
            # up to whitespace) already passed the logprob and
            # reverse-translation gates once — no need to re-spend SLM
            # calls re-verifying it. Only the device-context overlay below
            # (this job's own vendor/os/file hash) is ever applied fresh.
            raw_candidate = cached_candidate
            candidate = cached_candidate
        else:
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
            slm_result = await slm.generate(
                prompt,
                text,
                _grammar.json_schema(),
                device_context=device_context,
            )
            raw_candidate = slm_result.value
            mean_logprob = slm_result.mean_logprob
            candidate = normalize_candidate(raw_candidate)

            if mean_logprob is not None and mean_logprob < settings.logprob_uncertainty_threshold:
                return None, UnknownBlock(
                    chunk_index=chunk["index"],
                    text=text,
                    reason=(
                        f"low_token_confidence: mean_logprob={mean_logprob:.3f} "
                        f"< threshold={settings.logprob_uncertainty_threshold}"
                    ),
                    candidate=raw_candidate,
                )

            if settings.enable_reverse_translation:
                fidelity = await _check_reverse_translation_fidelity(
                    candidate, device_context, slm=slm, rag_context=rag_context
                )
                if fidelity is not None and fidelity < settings.reverse_translation_fidelity_threshold:
                    return None, UnknownBlock(
                        chunk_index=chunk["index"],
                        text=text,
                        reason=(
                            f"reverse_translation_fidelity_below_threshold: fidelity={fidelity:.3f} "
                            f"< threshold={settings.reverse_translation_fidelity_threshold}"
                        ),
                        candidate=raw_candidate,
                    )

            # Cache only a gate-passing candidate, pre-overlay (vendor/os/
            # hash are always re-applied fresh below, per job) — a failed
            # chunk is never cached, since it might succeed later with
            # better RAG context or an improved model.
            await cache.set(device_context.vendor, device_context.os, text, candidate)

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
    vendor_fingerprint_provider: VendorFingerprintProvider | None = None,
) -> dict[str, Any]:
    fingerprint_provider = vendor_fingerprint_provider or _vendor_fingerprint
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

    _dispatch_unknown_blocks(job["job_id"], device_context, unknown_blocks)

    if not baselines:
        detail = {
            "reason": "no_chunks_parsed",
            "detected_vendor": device_context.vendor,
            "detected_os": device_context.os,
            "confidence": device_context.confidence,
            "unknown_blocks_count": len(unknown_blocks),
        }
        await _add_semantic_vendor_guess(detail, device_context, job["chunks"], fingerprint_provider)
        await db.mark_needs_review(job["job_id"], detail)
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

    # Device-level confidence comes from extraction quality alone — never
    # from whether the regex fingerprinter recognized the vendor's name.
    # Flooring this against device_context.confidence (0.0 for anything the
    # fingerprinter doesn't know) would silently re-create a vendor
    # allowlist through the confidence math even after removing the
    # explicit one below: an unrecognized vendor the SLM nonetheless parsed
    # well must not be punished for a fingerprint miss.
    confidence = sum(chunk_confidences) / len(chunk_confidences)

    # Validation/parse failures reduce coverage, but do not collapse confidence
    # to zero. The published baseline is still gated below by the threshold.
    if job["chunks"] and unknown_blocks:
        failure_ratio = len(unknown_blocks) / len(job["chunks"])
        confidence *= max(0.0, 1.0 - 0.50 * failure_ratio)

    if conflicts:
        confidence = max(0.0, confidence - 0.05 * len(conflicts))

    merged.device.parsing_confidence = min(1.0, max(0.0, confidence))
    baseline_json = merged.model_dump(mode="json")

    # Vendor identity is no longer a gate — an unrecognized vendor is not
    # the same thing as an unparseable one. Whether this device reaches
    # Compliance depends solely on whether the SLM's own extraction was
    # good enough to trust, which the OPA bundle then evaluates identically
    # regardless of what vendor produced it.
    if merged.device.parsing_confidence < settings.confidence_threshold:
        detail = {
            "reason": "parsing_confidence_below_threshold",
            "detected_vendor": device_context.vendor,
            "detected_os": device_context.os,
            "confidence": merged.device.parsing_confidence,
            "unknown_blocks_count": len(unknown_blocks),
        }
        await _add_semantic_vendor_guess(detail, device_context, job["chunks"], fingerprint_provider)
        await db.mark_needs_review(job["job_id"], detail)
        return {
            "status": "human_review",
            "audit_run_id": job["job_id"],
            "baseline": baseline_json,
            "reason": "parsing_confidence_below_threshold",
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


def _job_text_sample(chunks: list[dict[str, Any]], *, max_chars: int = 4000) -> str:
    ordered = sorted(chunks, key=lambda item: item["index"])
    return "\n\n".join(str(chunk.get("text", "")) for chunk in ordered)[:max_chars]


async def _add_semantic_vendor_guess(
    detail: dict[str, Any],
    device_context: DeviceContext,
    chunks: list[dict[str, Any]],
    provider: VendorFingerprintProvider,
) -> None:
    """Mutate `detail` in place with a semantic vendor guess when regex
    detection came back unknown. Reporting-only: never changes device_context
    or any gating decision, only what an admin sees in status_detail.
    """
    if device_context.vendor != "unknown":
        return

    guess = await provider.identify(_job_text_sample(chunks))
    if guess is not None:
        detail["semantic_vendor_guess"] = {
            "vendor": guess.vendor,
            "os": guess.os,
            "confidence": guess.confidence,
        }


def _dispatch_unknown_blocks(job_id: str, device_context: DeviceContext, unknown_blocks: list[UnknownBlock]) -> None:
    """Push each block that failed schema validation to the Learning lane for
    human mapping. Fires regardless of the job's overall outcome — a chunk
    that failed validation needs review whether or not the rest of the
    device's baseline was good enough to publish.
    """
    context = _context_to_dict(device_context)
    for block in unknown_blocks:
        celery_app.send_task(
            "learning.receive_unknown_block",
            args=[
                {
                    "block_id": f"{job_id}:{block.chunk_index}",
                    "audit_run_id": job_id,
                    "raw_text": block.text,
                    "chunk_context": context,
                }
            ],
        )


if __name__ == "__main__":
    celery_app.worker_main(["worker", "--loglevel=info", "--concurrency=2"])
