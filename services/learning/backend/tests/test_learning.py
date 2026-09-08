import asyncio
import unittest
from unittest.mock import MagicMock, patch

from app.main import (
    LearningMapRequest,
    RAGSearchRequest,
    UnrecognizedBlock,
    get_learning_queue,
    health,
    search_learning,
    submit_learning_map,
)


class TestLearningService(unittest.TestCase):

    def test_health(self):
        result = asyncio.run(health())

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["service"], "learning")

    def test_mapping_is_stored(self):
        fake_collection = MagicMock()

        request = LearningMapRequest(
            block_id="test-1",
            cli_pattern="crypto isakmp policy 10 / hash sha256",
            field="crypto.ike.hash_algorithm",
            value="SHA256",
        )

        with patch(
            "app.main.get_collection",
            return_value=fake_collection,
        ):
            result = asyncio.run(
                submit_learning_map(request, "test-user")
            )

        self.assertTrue(result["confirmed"])
        self.assertEqual(result["block_id"], "test-1")
        fake_collection.upsert.assert_called_once()

    def test_rag_search(self):
        fake_collection = MagicMock()

        fake_collection.query.return_value = {
            "ids": [["test-1"]],
            "documents": [["SHA256 mapping"]],
            "metadatas": [[{"field": "crypto.ike.hash_algorithm"}]],
            "distances": [[0.1]],
        }

        request = RAGSearchRequest(
            query="ISAKMP policy using SHA256"
        )

        with patch(
            "app.main.get_collection",
            return_value=fake_collection,
        ):
            result = search_learning(request)

        self.assertEqual(
            result["query"],
            "ISAKMP policy using SHA256",
        )
        self.assertEqual(
            result["results"]["ids"][0][0],
            "test-1",
        )
        fake_collection.query.assert_called_once()

    def test_queue_response_shape(self):
        result = asyncio.run(get_learning_queue())

        self.assertIsInstance(result, list)

        block = UnrecognizedBlock(
            block_id="queue-test",
            raw_text="unknown network command",
        )

        self.assertEqual(block.block_id, "queue-test")
        self.assertEqual(block.raw_text, "unknown network command")


if __name__ == "__main__":
    unittest.main()
