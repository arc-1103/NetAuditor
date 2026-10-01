"""Optional cross-encoder re-ranking of the hybrid candidates.

A cross-encoder reads the query and each passage together, so it can judge
relevance the bi-encoder (BGE) and BM25 only approximate. Off by default
(RERANK_ENABLED=true): the model is a second download, which an air-gapped
site must pre-load. If it cannot load or run, the fused order is kept and
the response says so, so a missing model never breaks retrieval.

Only the order changes. Each match keeps its cosine distance, which is what
Parsing's trust gate uses.
"""
import logging
import os

logger = logging.getLogger(__name__)

RERANK_MODEL = os.getenv("RERANK_MODEL", "BAAI/bge-reranker-base")
_model = None


def _default_scorer(query: str, documents: list[str]) -> list[float]:
    global _model
    if _model is None:
        from sentence_transformers import CrossEncoder

        _model = CrossEncoder(RERANK_MODEL)
    return [float(s) for s in _model.predict([(query, d) for d in documents])]


def rerank(results: dict, query: str, top_k: int, scorer=None) -> dict:
    ids = (results.get("ids") or [[]])[0]
    if not ids:
        return results
    docs = (results.get("documents") or [[]])[0]
    try:
        scores = (scorer or _default_scorer)(query, docs)
    except Exception as exc:  # model missing/offline: keep the fused order
        logger.warning("Cross-encoder rerank unavailable, keeping fused order: %s", exc)
        return {**_take(results, list(range(min(top_k, len(ids))))), "rerank": f"skipped: {exc.__class__.__name__}"}
    order = sorted(range(len(ids)), key=lambda i: (-scores[i], i))[:top_k]
    out = _take(results, order)
    out["rerank_scores"] = [[round(scores[i], 6) for i in order]]
    out["rerank"] = RERANK_MODEL
    return out


def _take(results: dict, order: list[int]) -> dict:
    out = dict(results)
    for key in ("ids", "documents", "metadatas", "distances", "fusion_scores"):
        if results.get(key):
            out[key] = [[results[key][0][i] for i in order]]
    return out
