"""Hybrid retrieval: dense (BGE cosine) + lexical (BM25), fused with RRF.

Dense embeddings treat `ip access-group 101 in` and `ip access-group 102 in`
as near-identical; BM25 on whole CLI tokens tells them apart. The two rankings
are combined by reciprocal rank fusion, which needs no score calibration.

The BM25 corpus is the dense candidate set (already vendor/OS pre-filtered),
so lexical matching can never pull in another vendor's mappings. Each result
keeps its true cosine distance: the caller's trust gate (Parsing's CRAG
corrector) still decides on distance, fusion only changes the order.
"""
import math
import re
from collections import Counter

_TOKEN = re.compile(r"[a-z0-9_.:/-]+")
RRF_K = 60


def tokenize(text: str) -> list[str]:
    return _TOKEN.findall((text or "").lower())


def bm25_scores(query: str, documents: list[str], k1: float = 1.5, b: float = 0.75) -> list[float]:
    docs = [tokenize(d) for d in documents]
    n = len(docs)
    avg = (sum(len(d) for d in docs) / n) if n else 0.0
    df = Counter(t for d in docs for t in set(d))
    scores = []
    for d in docs:
        tf = Counter(d)
        s = 0.0
        for t in set(tokenize(query)):
            if t not in tf:
                continue
            idf = math.log(1 + (n - df[t] + 0.5) / (df[t] + 0.5))
            s += idf * tf[t] * (k1 + 1) / (tf[t] + k1 * (1 - b + b * len(d) / (avg or 1)))
        scores.append(s)
    return scores


def fuse(results: dict, query: str, top_k: int) -> dict:
    """Re-rank a chromadb `query` result (one query) by RRF of dense order and
    BM25 order. Same shape out, trimmed to top_k, distances untouched."""
    ids = (results.get("ids") or [[]])[0]
    if not ids:
        return results
    docs = (results.get("documents") or [[]])[0]
    metas = (results.get("metadatas") or [[None] * len(ids)])[0]
    dists = (results.get("distances") or [[0.0] * len(ids)])[0]

    dense_rank = {i: r for r, i in enumerate(range(len(ids)))}  # chromadb returns nearest first
    lexical = bm25_scores(query, docs)
    lex_order = sorted(range(len(ids)), key=lambda i: -lexical[i])
    lex_rank = {i: r for r, i in enumerate(lex_order) if lexical[i] > 0}  # no token overlap = no vote

    def rrf(i: int) -> float:
        return 1 / (RRF_K + dense_rank[i]) + (1 / (RRF_K + lex_rank[i]) if i in lex_rank else 0.0)

    order = sorted(range(len(ids)), key=lambda i: (-rrf(i), i))[:top_k]
    return {
        "ids": [[ids[i] for i in order]],
        "documents": [[docs[i] for i in order]],
        "metadatas": [[metas[i] for i in order]],
        "distances": [[dists[i] for i in order]],
        "fusion_scores": [[round(rrf(i), 6) for i in order]],
        "retrieval": "hybrid: dense cosine + BM25, reciprocal rank fusion",
    }
