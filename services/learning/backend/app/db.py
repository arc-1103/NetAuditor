"""
Postgres access for the Learning lane's review queue. Owns the
`learning_queue` table (see infra/postgres/init.sql); mirrors
services/compliance/app/db.py's connection pattern for the shared
Postgres instance.
"""

import json
import os

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

POSTGRES_DSN = os.getenv(
    "POSTGRES_DSN",
    "postgresql+asyncpg://netaudit:changeme_in_local_env@postgres:5432/netaudit",
)

engine = create_async_engine(POSTGRES_DSN, echo=False)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def enqueue_block(
    block_id: str,
    audit_run_id: str,
    raw_text: str,
    chunk_context: dict | None = None,
) -> None:
    """Insert a block awaiting human mapping, or refresh it if already queued.

    `block_id` is deterministic (e.g. "<audit_run_id>:<chunk_index>"), so a
    caller can safely re-submit the same block without creating a duplicate
    row or losing an in-progress mapping's status.
    """
    async with async_session() as session, session.begin():
        await session.execute(
            text(
                """
                INSERT INTO learning_queue (block_id, audit_run_id, raw_text, chunk_context, status)
                VALUES (:block_id, :audit_run_id, :raw_text, :chunk_context, 'PENDING')
                ON CONFLICT (block_id) DO UPDATE SET
                    raw_text = EXCLUDED.raw_text,
                    chunk_context = EXCLUDED.chunk_context
                """
            ),
            {
                "block_id": block_id,
                "audit_run_id": audit_run_id,
                "raw_text": raw_text,
                "chunk_context": json.dumps(chunk_context or {}),
            },
        )


async def get_pending_blocks() -> list[dict]:
    """Oldest-first queue of blocks still awaiting a human mapping."""
    async with async_session() as session:
        rows = (
            await session.execute(
                text(
                    """
                    SELECT block_id, audit_run_id, raw_text, chunk_context, status, created_at
                    FROM learning_queue
                    WHERE status = 'PENDING'
                    ORDER BY created_at
                    """
                )
            )
        ).mappings().all()
    return [_jsonable(row) for row in rows]


async def mark_mapped(block_id: str) -> bool:
    """Mark a queued block MAPPED. Returns False when the block wasn't
    pending (already resolved, or never queued) so the caller can tell a
    confirmed mapping apart from one that had no matching queue entry.
    """
    async with async_session() as session, session.begin():
        result = await session.execute(
            text(
                """
                UPDATE learning_queue SET status = 'MAPPED'
                WHERE block_id = :block_id AND status = 'PENDING'
                RETURNING block_id
                """
            ),
            {"block_id": block_id},
        )
    return result.scalar_one_or_none() is not None


def _jsonable(row) -> dict:
    """UUID/datetime columns come back as objects; FastAPI needs them as
    strings, and chunk_context needs to come back as an object, not the
    JSON-encoded string it's stored/bound as."""
    value = json.loads(json.dumps(dict(row), default=str))
    if isinstance(value.get("chunk_context"), str):
        value["chunk_context"] = json.loads(value["chunk_context"])
    return value
