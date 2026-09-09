from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class VendorDetection:
    vendor: str
    os: str | None
    os_version: str | None
    raw_hostname: str | None
    hardware_model: str | None
    confidence: float
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class DeviceContext:
    """Device identity established once for an ingestion job."""

    vendor: str
    os: str | None
    os_version: str | None
    raw_hostname: str | None
    hardware_model: str | None
    confidence: float
    evidence: tuple[str, ...] = ()


@dataclass
class UnknownBlock:
    chunk_index: int
    text: str
    reason: str
    fields: list[str] = field(default_factory=list)
    candidate: Any | None = None


@dataclass
class ParseResult:
    baseline: Any
    unknown_blocks: list[UnknownBlock]
    chunk_confidences: list[float]


@dataclass(frozen=True)
class SLMResult:
    """Return shape of `SLMClient.generate`.

    `mean_logprob` is the mean per-token log-probability the model reported
    for the generated JSON, or `None` when the backend didn't supply
    logprobs (e.g. an Ollama version without per-token logprob output).
    `None` means "no signal" — it must not be treated as low confidence.
    """

    value: dict[str, Any]
    mean_logprob: float | None = None
