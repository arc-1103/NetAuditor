from __future__ import annotations

from typing import Protocol


class RAGContextProvider(Protocol):
    """Injectable optional provider owned by the Learning/RAG lane."""

    async def retrieve(self, vendor: str, os_name: str | None, config_text: str) -> str:
        """Return trusted few-shot context, or an empty string when unavailable."""
        ...


class EmptyRAGContextProvider:
    """Safe default: Parsing works when ChromaDB/Learning is unavailable."""

    async def retrieve(self, vendor: str, os_name: str | None, config_text: str) -> str:
        return ""
