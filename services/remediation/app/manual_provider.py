"""Client for Learning's remediation-manual index
(services/learning/backend/app/main.py `/learning/remediation-manuals*`).

Optional enrichment, same resilience pattern as Parsing's
`RAGContextProvider`/`VendorFingerprintProvider`: an unreachable Learning
service degrades to "no manual context found" rather than raising, and
app/rag_remediation.py treats that as ungrounded synthesis — not a hard
failure, but a mandatory risk flag on the resulting proposal.
"""

from __future__ import annotations

from typing import Protocol

import httpx


class RemediationManualProvider(Protocol):
    async def lookup(self, vendor: str, os_name: str | None, control_id: str) -> list[str]:
        """Vendor manual excerpts indexed under this exact [control_id,
        vendor, OS] key, or an empty list when none are indexed or the
        lookup service is unavailable."""
        ...


class EmptyRemediationManualProvider:
    """Safe default: the agentic RAG fallback still runs (marked ungrounded)
    when Learning is unavailable or unconfigured."""

    async def lookup(self, vendor: str, os_name: str | None, control_id: str) -> list[str]:
        return []


class LearningRemediationManualProvider:
    def __init__(self, base_url: str, *, timeout_seconds: float = 5.0):
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    async def lookup(self, vendor: str, os_name: str | None, control_id: str) -> list[str]:
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.post(
                    f"{self.base_url}/learning/remediation-manuals/search",
                    json={"vendor": vendor, "os": os_name, "control_id": control_id},
                )
                response.raise_for_status()
                body = response.json()
        except (httpx.HTTPError, ValueError):
            return []
        return body.get("manual_excerpts") or []
