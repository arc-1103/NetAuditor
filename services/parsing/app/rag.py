from __future__ import annotations

import re
from typing import Protocol

import httpx


def _tokens(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", text.lower()))


class RAGContextProvider(Protocol):
    """Injectable optional provider owned by the Learning/RAG lane."""

    async def retrieve(self, vendor: str, os_name: str | None, config_text: str) -> str:
        """Return trusted few-shot context, or an empty string when unavailable."""
        ...


class EmptyRAGContextProvider:
    """Safe default: Parsing works when ChromaDB/Learning is unavailable."""

    async def retrieve(self, vendor: str, os_name: str | None, config_text: str) -> str:
        return ""


class LearningRAGContextProvider:
    """Retrieves confirmed CLI-to-security-field mappings from the
    Learning/RAG lane's `/learning/search` endpoint and formats trusted
    matches as few-shot context for the SLM prompt.

    The query is now pre-filtered by vendor/OS server-side (main.py's
    `search_learning`) before similarity search runs at all — retrieving a
    Juniper mapping for a Cisco chunk was a real, live bug this fixes:
    never do open-ended vector search across every vendor's confirmed
    mappings at once.

    This is Corrective RAG (CRAG): embedding distance alone grades each
    match into one of three bands, and only the middle band gets a second,
    independent check before being trusted —

      - distance <= correct_max_distance   -> CORRECT: trust outright.
      - <= ambiguous_max_distance            -> AMBIGUOUS: trust only if the
        confirmed mapping's actual `cli_pattern` (from its stored metadata)
        literally shows up in the chunk being parsed right now. A close
        embedding says "this looks similar"; the pattern check says "and
        here is the literal evidence it applies to THIS chunk" — for CLI
        syntax, which either is or isn't present in the text, a literal miss
        outweighs a close-but-unconfirmed embedding.
      - beyond ambiguous_max_distance        -> INCORRECT: dropped, no
        correction attempted.

    The CRAG paper's third action for INCORRECT documents is to fall back to
    an external knowledge source (e.g. web search); this pipeline has none
    available, so a match that fails correction is simply dropped — the SLM
    parses the chunk with no few-shot context, identical to a Learning/RAG
    outage. A distant or uncorroborated match is worse than no context at
    all, the same reasoning vendor_fingerprint.py applies to its own
    distance cutoff.
    """

    def __init__(
        self,
        base_url: str,
        *,
        timeout_seconds: float = 5.0,
        correct_max_distance: float = 0.4,
        ambiguous_max_distance: float = 0.8,
        pattern_overlap_threshold: float = 0.6,
        top_k: int = 3,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.correct_max_distance = correct_max_distance
        self.ambiguous_max_distance = ambiguous_max_distance
        self.pattern_overlap_threshold = pattern_overlap_threshold
        self.top_k = top_k

    async def retrieve(self, vendor: str, os_name: str | None, config_text: str) -> str:
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.post(
                    f"{self.base_url}/learning/search",
                    json={"query": config_text, "vendor": vendor, "os": os_name},
                )
                response.raise_for_status()
                body = response.json()
        except (httpx.HTTPError, ValueError):
            return ""

        return self._correct(body.get("results") or {}, config_text)

    def _correct(self, results: dict, config_text: str) -> str:
        documents = (results.get("documents") or [[]])[0]
        distances = (results.get("distances") or [[]])[0]
        metadatas = (results.get("metadatas") or [[]])[0]

        trusted = []
        # chromadb returns matches sorted by ascending distance, so the first
        # one past the ambiguous band means every match after it is farther
        # still — nothing later can qualify either.
        for document, distance, metadata in zip(documents, distances, metadatas):
            if distance > self.ambiguous_max_distance:
                break
            if distance <= self.correct_max_distance or self._pattern_confirmed(metadata, config_text):
                trusted.append(document)
            if len(trusted) >= self.top_k:
                break

        return "\n\n".join(trusted)

    def _pattern_confirmed(self, metadata: dict | None, config_text: str) -> bool:
        cli_pattern = (metadata or {}).get("cli_pattern")
        if not cli_pattern:
            return False

        pattern_tokens = _tokens(cli_pattern)
        if not pattern_tokens:
            return False

        overlap = pattern_tokens & _tokens(config_text)
        return len(overlap) / len(pattern_tokens) >= self.pattern_overlap_threshold
