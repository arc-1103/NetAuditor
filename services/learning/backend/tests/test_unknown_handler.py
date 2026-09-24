"""
Tests for the Celery task's payload handling. The queue write itself is
covered by tests/test_db.py — what matters here is that a malformed block
from the Parsing lane fails loudly instead of being silently dropped, and
that a valid one reaches app.db.enqueue_block with the right arguments.
"""

import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from app import unknown_handler

RUN_ID = "11111111-1111-1111-1111-111111111111"


class TestUnknownHandler(unittest.TestCase):
    def test_task_is_registered_under_the_contract_name(self):
        """Parsing sends `learning.receive_unknown_block` — renaming it
        silently breaks the hop, since Celery just queues the unknown task."""
        self.assertEqual(unknown_handler.receive_unknown_block.name, "learning.receive_unknown_block")

    def test_task_enqueues_the_block(self):
        block = {
            "block_id": f"{RUN_ID}:0",
            "audit_run_id": RUN_ID,
            "raw_text": "no ip http server",
            "chunk_context": {"vendor": "cisco"},
        }
        spy = AsyncMock(return_value=None)

        with patch.object(unknown_handler.db, "enqueue_block", spy):
            result = unknown_handler.receive_unknown_block(block)

        self.assertEqual(result, {"queued": True, "block_id": f"{RUN_ID}:0"})
        spy.assert_awaited_once_with(f"{RUN_ID}:0", RUN_ID, "no ip http server", {"vendor": "cisco"})

    def test_task_rejects_a_block_without_a_block_id(self):
        with self.assertRaisesRegex(ValueError, "block_id"):
            unknown_handler.receive_unknown_block({"audit_run_id": RUN_ID, "raw_text": "x"})

    def test_task_rejects_a_block_without_an_audit_run_id(self):
        with self.assertRaisesRegex(ValueError, "audit_run_id"):
            unknown_handler.receive_unknown_block({"block_id": "b1", "raw_text": "x"})

    def test_task_rejects_a_block_without_raw_text(self):
        with self.assertRaisesRegex(ValueError, "raw_text"):
            unknown_handler.receive_unknown_block({"block_id": "b1", "audit_run_id": RUN_ID})

    def test_worker_reuses_one_event_loop_across_tasks(self):
        """asyncio.run() opens a fresh loop and closes it on every call,
        which breaks the module-level asyncpg pool on the second task in a
        worker process (its connections stay bound to the first, now-closed
        loop). _run must actually execute every task on the same persistent
        loop instead."""
        block = {"block_id": f"{RUN_ID}:0", "audit_run_id": RUN_ID, "raw_text": "x"}
        seen_loops = []

        async def fake_enqueue_block(*args, **kwargs):
            seen_loops.append(asyncio.get_running_loop())

        with patch.object(unknown_handler.db, "enqueue_block", fake_enqueue_block):
            unknown_handler.receive_unknown_block(block)
            unknown_handler.receive_unknown_block(block)

        self.assertEqual(len(seen_loops), 2)
        self.assertIs(seen_loops[0], seen_loops[1])
        self.assertIs(seen_loops[0], unknown_handler._loop)
        self.assertFalse(unknown_handler._loop.is_closed())


if __name__ == "__main__":
    unittest.main()
