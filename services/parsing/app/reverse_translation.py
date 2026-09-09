"""
Multi-agent reverse translation.

Agent A is the existing forward pipeline (slm_client.OllamaSLMClient.generate):
CLI text in, normalized JSON out. Agent B (OllamaSLMClient.reverse_translate)
takes ONLY that JSON — never the original text — and reconstructs plausible
CLI. Re-running Agent A on Agent B's reconstruction and diffing the two JSON
candidates verifies the round trip lost none of what Agent A claimed to
observe: if Agent A hallucinated a field or silently dropped one, the
reconstruction (grounded in the wrong or incomplete JSON) won't reproduce
it, and the diff below catches that.

This lives in worker.py's _parse_chunk as an additional gate alongside the
logprob-uncertainty check, not a replacement for it: a chunk can pass one
and fail the other, and each catches a different failure mode.
"""

from __future__ import annotations

from typing import Any

# Fields set by the worker/normalizer from device_context or the file hash,
# not from what Agent A actually read out of the chunk text — a mismatch
# here says nothing about extraction fidelity, so they're excluded from the
# diff the same way GraphRAG topology is excluded from parsing_confidence.
_DEVICE_FIELDS_EXCLUDED_FROM_FIDELITY = {
    "detected_vendor",
    "detected_os",
    "detected_os_version",
    "detected_hardware_model",
    "config_sha256",
    "parsing_confidence",
    "unknown_blocks_count",
}


# "Not observed" sentinels across the schema's enums (ProtocolStatus.UNKNOWN,
# SSHVersion.NONE, SNMPVersion.NONE, HashAlgorithm.NONE/UNKNOWN,
# EncryptionAlgorithm.NONE/UNKNOWN) plus the ordinary empty-value cases —
# none of these represent a fact Agent A actually extracted, so a round trip
# that "loses" one hasn't lost anything real.
_PLACEHOLDER_VALUES = {None, "", "UNKNOWN", "unknown", "NONE", "none"}


def _leaf_facts(candidate: dict[str, Any]) -> set[tuple[str, str]]:
    """Flatten a normalized candidate into (path, value) pairs. Order-
    independent (a reordered list isn't data loss) and blind to placeholder
    values (the absence of a fact isn't a fact to lose)."""
    facts: set[tuple[str, str]] = set()

    def _walk(prefix: str, value: Any) -> None:
        if isinstance(value, dict):
            for key, val in value.items():
                if prefix == "device" and key in _DEVICE_FIELDS_EXCLUDED_FROM_FIDELITY:
                    continue
                _walk(f"{prefix}.{key}" if prefix else key, val)
        elif isinstance(value, list):
            for item in value:
                _walk(prefix, item)
        elif value not in _PLACEHOLDER_VALUES:
            facts.add((prefix, str(value)))

    _walk("", candidate)
    return facts


def compute_fidelity(original: dict[str, Any], roundtrip: dict[str, Any]) -> float:
    """Fraction of the facts Agent A extracted from the original chunk that
    survived the JSON -> CLI -> JSON round trip.

    1.0 when Agent A extracted nothing observable (topology-only or fully
    empty chunks included — there is nothing to lose) or the round trip is
    a perfect match. 0.0 when everything Agent A found vanished.
    """
    original_facts = _leaf_facts(original)
    if not original_facts:
        return 1.0

    roundtrip_facts = _leaf_facts(roundtrip)
    return len(original_facts & roundtrip_facts) / len(original_facts)
