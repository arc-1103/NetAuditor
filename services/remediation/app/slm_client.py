"""SLM client for the agentic RAG remediation fallback (app/rag_remediation.py).

Only exercised when a finding's vendor has no committed .j2 template — every
other remediation stays on the deterministic app/template_engine.py path,
per the service's safety model (see README.md). Structurally the same
approach as services/parsing/app/slm_client.py: JSON-schema-constrained
generation via Ollama's `format` field, with a mock mode for offline
development and tests.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

RESPONSE_SCHEMA = {
    "type": "object",
    "required": ["remediation_cli", "rollback_cli"],
    "properties": {
        "remediation_cli": {"type": "string"},
        "unified_diff": {"type": "string"},
        "rollback_cli": {"type": "string"},
    },
}


class SLMError(RuntimeError):
    pass


class OllamaSLMClient:
    def __init__(self, host: str, model: str, *, timeout_seconds: float = 60.0, mock: bool = False):
        self.host = host.rstrip("/")
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.mock = mock

    async def synthesize(self, prompt: str) -> dict[str, Any]:
        if self.mock:
            return self._mock_response()

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": RESPONSE_SCHEMA,
            "options": {"temperature": 0},
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.post(f"{self.host}/api/generate", json=payload)
                response.raise_for_status()
                body = response.json()
        except httpx.TimeoutException as exc:
            raise SLMError("Ollama request timed out") from exc
        except (httpx.HTTPError, ValueError) as exc:
            raise SLMError(f"Ollama request failed: {exc}") from exc

        raw = body.get("response")
        if not isinstance(raw, str):
            raise SLMError("Ollama response did not contain a string 'response' field")
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SLMError("Ollama returned invalid JSON") from exc
        if not isinstance(value, dict):
            raise SLMError("Ollama JSON response must be an object")
        return value

    def _mock_response(self) -> dict[str, Any]:
        """Deterministic placeholder for offline dev/tests. Never reads the
        prompt to invent commands — it only proves the plumbing between
        app/rag_remediation.py, this client, and app/main.py; it is not a
        stand-in for real vendor-CLI knowledge the way Parsing's mock SLM is
        for config extraction."""
        return {
            "remediation_cli": "! mock agentic-rag remediation command",
            "unified_diff": "--- before\n+++ after\n",
            "rollback_cli": "! mock agentic-rag rollback command",
        }
