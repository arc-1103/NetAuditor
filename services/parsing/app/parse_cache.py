"""
Exact-hash parse cache.

Enterprise fleets repeat the same NTP/Syslog/AAA blocks, byte-identical up
to whitespace, across hundreds of devices. A hit skips RAG retrieval and
the SLM generate() call entirely — a chunk that already passed the logprob
and reverse-translation gates once needs no re-verification the second
time.

Keyed by SHA-256 of [vendor, os, normalized chunk text] in Redis — O(1),
no vector DB or model involved. A separate Redis logical database
(PARSE_CACHE_REDIS_URL, default db 1) from the Celery broker (db 0): same
Redis instance, distinct keyspace, so a cache flush can never touch queued
Celery messages and vice versa.

Only successful, gate-passing parses are cached — a failure is never
cached, since the same chunk might succeed later with better RAG context
or an improved model.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from typing import Any, Protocol

logger = logging.getLogger(__name__)

# An unreachable Redis must fail fast, not hang the whole parse — redis-py's
# own defaults have no connect/socket timeout at all, which turns "Redis is
# down" into "this chunk parse blocks for the OS's TCP timeout" instead of
# the sub-second miss this optional cache is supposed to cost at worst.
_CONNECT_TIMEOUT_SECONDS = 0.3
_OPERATION_TIMEOUT_SECONDS = 0.5


def _normalize(text: str) -> str:
    """Whitespace-only normalization. Meaningful content (case, exact
    values) is preserved — a hostname or community-string difference is a
    real difference, not noise to collapse away."""
    lines = [line.rstrip() for line in text.splitlines()]
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines)


def cache_key(vendor: str, os_name: str | None, config_text: str) -> str:
    digest = hashlib.sha256(f"{vendor}\x00{os_name or ''}\x00{_normalize(config_text)}".encode()).hexdigest()
    return f"parse-cache:{digest}"


class ParseCacheProvider(Protocol):
    async def get(self, vendor: str, os_name: str | None, config_text: str) -> dict[str, Any] | None:
        """Cached normalized candidate dict, or None on a miss."""
        ...

    async def set(self, vendor: str, os_name: str | None, config_text: str, candidate: dict[str, Any]) -> None:
        ...


class EmptyParseCacheProvider:
    """Safe default: parsing works with ENABLE_PARSE_CACHE=false or an
    unreachable Redis — every lookup is just a miss."""

    async def get(self, vendor: str, os_name: str | None, config_text: str) -> dict[str, Any] | None:
        return None

    async def set(self, vendor: str, os_name: str | None, config_text: str, candidate: dict[str, Any]) -> None:
        return None


class RedisExactParseCache:
    """A miss here is the normal, expected case for any chunk not seen
    before — it is not evidence of an outage."""

    def __init__(self, redis_url: str):
        self._redis_url = redis_url
        self._client = None

    def _get_client(self):
        if self._client is None:
            import redis.asyncio as redis

            self._client = redis.Redis.from_url(
                self._redis_url,
                decode_responses=True,
                socket_connect_timeout=_CONNECT_TIMEOUT_SECONDS,
                socket_timeout=_OPERATION_TIMEOUT_SECONDS,
            )
        return self._client

    async def get(self, vendor: str, os_name: str | None, config_text: str) -> dict[str, Any] | None:
        try:
            raw = await asyncio.wait_for(
                self._get_client().get(cache_key(vendor, os_name, config_text)),
                timeout=_OPERATION_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            logger.warning("Exact parse cache unavailable: %s", exc)
            return None
        return json.loads(raw) if raw else None

    async def set(self, vendor: str, os_name: str | None, config_text: str, candidate: dict[str, Any]) -> None:
        try:
            await asyncio.wait_for(
                self._get_client().set(cache_key(vendor, os_name, config_text), json.dumps(candidate)),
                timeout=_OPERATION_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            logger.warning("Failed to write exact parse cache: %s", exc)


def build_parse_cache_provider(*, enabled: bool, redis_url: str) -> ParseCacheProvider:
    if not enabled:
        return EmptyParseCacheProvider()
    return RedisExactParseCache(redis_url)
