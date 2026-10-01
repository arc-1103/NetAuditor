"""Semantic cache for /learning/search.

A repeat or near-repeat query (same wording up to embedding noise) returns the
stored retrieval result without another ChromaDB round trip.

Safety rules, because in CLI text a near-identical string can mean something
different:
  * a hit needs the same vendor and OS scope, so a cached Cisco result is
    never served for a Juniper query;
  * cosine similarity >= SEMANTIC_CACHE_THRESHOLD (default 0.98), and the
    tokens that contain digits must match exactly, so `access-group 101`
    never reuses the result for `access-group 102`;
  * any new confirmed mapping clears the cache, so a human's correction is
    visible on the next query;
  * entries expire after SEMANTIC_CACHE_TTL_SECONDS (default 1 hour).

This caches retrieval only. It is deliberately NOT applied to model output:
serving a near-match's extraction could return another device's values.
In-process, per worker, bounded, and lost on restart.
"""
import os
import re
import time

import numpy as np

THRESHOLD = float(os.getenv("SEMANTIC_CACHE_THRESHOLD", "0.98"))
TTL_SECONDS = float(os.getenv("SEMANTIC_CACHE_TTL_SECONDS", "3600"))
MAX_ENTRIES = int(os.getenv("SEMANTIC_CACHE_MAX_ENTRIES", "256"))

_DIGIT_TOKEN = re.compile(r"\S*\d\S*")
_entries: list[dict] = []
stats = {"hits": 0, "misses": 0}


def _numbers(text: str) -> frozenset:
    return frozenset(_DIGIT_TOKEN.findall((text or "").lower()))


def _cosine(a, b) -> float:
    a, b = np.asarray(a, dtype=float), np.asarray(b, dtype=float)
    denom = np.linalg.norm(a) * np.linalg.norm(b)
    return float(a @ b / denom) if denom else 0.0


def lookup(query: str, vector, scope: tuple, now: float | None = None) -> dict | None:
    now = time.time() if now is None else now
    _entries[:] = [e for e in _entries if now - e["at"] <= TTL_SECONDS]
    numbers = _numbers(query)
    best = max(
        (e for e in _entries if e["scope"] == scope and e["numbers"] == numbers),
        key=lambda e: _cosine(vector, e["vector"]),
        default=None,
    )
    if best is not None and _cosine(vector, best["vector"]) >= THRESHOLD:
        stats["hits"] += 1
        return best["result"]
    stats["misses"] += 1
    return None


def store(query: str, vector, scope: tuple, result: dict, now: float | None = None) -> None:
    _entries.append({"scope": scope, "numbers": _numbers(query), "vector": list(vector), "result": result,
                     "at": time.time() if now is None else now})
    del _entries[:-MAX_ENTRIES]


def clear() -> None:
    _entries.clear()
