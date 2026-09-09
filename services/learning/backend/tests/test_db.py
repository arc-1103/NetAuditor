"""
Unit tests for app.db against an in-memory SQLite database standing in for
Postgres — same approach as services/compliance/tests/test_db.py. The
statements are plain SQL apart from the upsert/RETURNING syntax, which
SQLite also supports.
"""

import unittest

from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app import db

RUN_ID = "11111111-1111-1111-1111-111111111111"


class TestLearningQueueDb(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with self.engine.begin() as conn:
            await conn.execute(
                text(
                    """
                    CREATE TABLE learning_queue (
                        block_id      TEXT PRIMARY KEY,
                        audit_run_id  TEXT NOT NULL,
                        raw_text      TEXT NOT NULL,
                        chunk_context TEXT NOT NULL DEFAULT '{}',
                        status        TEXT NOT NULL DEFAULT 'PENDING',
                        created_at    TEXT
                    )
                    """
                )
            )

        self._original_session = db.async_session
        db.async_session = async_sessionmaker(self.engine, expire_on_commit=False)

    async def asyncTearDown(self):
        db.async_session = self._original_session
        await self.engine.dispose()

    async def test_enqueue_then_read_back_pending(self):
        await db.enqueue_block(f"{RUN_ID}:0", RUN_ID, "no ip http server", {"vendor": "cisco"})

        blocks = await db.get_pending_blocks()

        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0]["block_id"], f"{RUN_ID}:0")
        self.assertEqual(blocks[0]["raw_text"], "no ip http server")
        self.assertEqual(blocks[0]["chunk_context"], {"vendor": "cisco"})
        self.assertEqual(blocks[0]["status"], "PENDING")

    async def test_enqueue_is_idempotent_for_the_same_block_id(self):
        """A re-submitted block (e.g. Parsing retries) updates in place
        rather than creating a duplicate queue entry."""
        block_id = f"{RUN_ID}:1"
        await db.enqueue_block(block_id, RUN_ID, "first text", {})
        await db.enqueue_block(block_id, RUN_ID, "updated text", {"vendor": "juniper"})

        blocks = await db.get_pending_blocks()

        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0]["raw_text"], "updated text")
        self.assertEqual(blocks[0]["chunk_context"], {"vendor": "juniper"})

    async def test_mark_mapped_removes_block_from_pending_queue(self):
        block_id = f"{RUN_ID}:2"
        await db.enqueue_block(block_id, RUN_ID, "text", {})

        was_queued = await db.mark_mapped(block_id)

        self.assertTrue(was_queued)
        self.assertEqual(await db.get_pending_blocks(), [])

    async def test_mark_mapped_returns_false_for_a_block_that_was_never_queued(self):
        was_queued = await db.mark_mapped("does-not-exist")

        self.assertFalse(was_queued)

    async def test_mark_mapped_is_not_reapplied_to_an_already_mapped_block(self):
        block_id = f"{RUN_ID}:3"
        await db.enqueue_block(block_id, RUN_ID, "text", {})
        await db.mark_mapped(block_id)

        was_queued_again = await db.mark_mapped(block_id)

        self.assertFalse(was_queued_again)


if __name__ == "__main__":
    unittest.main()
