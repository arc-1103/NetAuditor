"""
Optional semantic vendor-guess provider, owned by the Learning/RAG lane.

Used only to enrich a human_review record when regex-based vendor detection
(vendor_detector.py) can't identify a device — it never feeds parsing itself.
A confident but wrong guess for a vendor we don't actually support yet
(no normalizer/rego/remediation coverage) would produce a plausible-looking
but meaningless baseline, so the guess is reporting-only: it changes what an
admin sees in status_detail, never what SUPPORTED_VENDORS gates or what the
SLM is prompted with.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import httpx


@dataclass(frozen=True)
class VendorGuess:
    vendor: str
    os: str | None
    confidence: float


class VendorFingerprintProvider(Protocol):
    async def identify(self, text: str) -> VendorGuess | None:
        """Return a best-effort vendor guess for `text`, or None when no
        confident match exists or the Learning lane is unavailable."""
        ...


class EmptyVendorFingerprintProvider:
    """Safe default: Parsing works when ChromaDB/Learning is unavailable."""

    async def identify(self, text: str) -> VendorGuess | None:
        return None


class LearningVendorFingerprintProvider:
    def __init__(self, base_url: str, *, timeout_seconds: float = 5.0):
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    async def identify(self, text: str) -> VendorGuess | None:
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.post(
                    f"{self.base_url}/learning/vendor-lookup", json={"text": text}
                )
                response.raise_for_status()
                body = response.json()
        except (httpx.HTTPError, ValueError):
            return None

        vendor = body.get("vendor")
        if not vendor:
            return None

        return VendorGuess(
            vendor=vendor,
            os=body.get("os"),
            confidence=float(body.get("confidence", 0.0)),
        )
