import asyncio
import unittest
from unittest.mock import MagicMock, patch

from app.main import (
    LearningMapRequest,
    RAGSearchRequest,
    UnknownBlockRequest,
    UnrecognizedBlock,
    VendorFingerprintRequest,
    VendorLookupRequest,
    add_vendor_fingerprint,
    enqueue_unknown_block,
    get_learning_queue,
    health,
    lookup_vendor,
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
        ), patch(
            "app.main.db.mark_mapped",
            return_value=True,
        ) as mark_mapped:
            result = asyncio.run(
                submit_learning_map(request, "test-user")
            )

        self.assertTrue(result["confirmed"])
        self.assertEqual(result["block_id"], "test-1")
        self.assertTrue(result["was_queued"])
        fake_collection.upsert.assert_called_once()
        mark_mapped.assert_called_once_with("test-1")

    def test_mapping_confirmed_even_when_block_was_never_queued(self):
        fake_collection = MagicMock()

        request = LearningMapRequest(
            block_id="never-queued",
            cli_pattern="crypto isakmp policy 10 / hash sha256",
            field="crypto.ike.hash_algorithm",
            value="SHA256",
        )

        with patch(
            "app.main.get_collection",
            return_value=fake_collection,
        ), patch(
            "app.main.db.mark_mapped",
            return_value=False,
        ):
            result = asyncio.run(
                submit_learning_map(request, "test-user")
            )

        self.assertTrue(result["confirmed"])
        self.assertFalse(result["was_queued"])

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
        with patch(
            "app.main.db.get_pending_blocks",
            return_value=[{"block_id": "queue-test", "raw_text": "unknown network command"}],
        ):
            result = asyncio.run(get_learning_queue())

        self.assertIsInstance(result, list)

        block = UnrecognizedBlock(
            block_id="queue-test",
            raw_text="unknown network command",
        )

        self.assertEqual(block.block_id, "queue-test")
        self.assertEqual(block.raw_text, "unknown network command")

    def test_get_learning_queue_reads_from_db(self):
        with patch(
            "app.main.db.get_pending_blocks",
            return_value=[{"block_id": "a", "raw_text": "text-a"}],
        ) as get_pending_blocks:
            result = asyncio.run(get_learning_queue())

        get_pending_blocks.assert_called_once_with()
        self.assertEqual(result, [{"block_id": "a", "raw_text": "text-a"}])

    def test_enqueue_unknown_block(self):
        request = UnknownBlockRequest(
            block_id="run-1:3",
            audit_run_id="run-1",
            raw_text="unrecognized cli block",
            chunk_context={"vendor": "cisco"},
        )

        with patch(
            "app.main.db.enqueue_block",
            return_value=None,
        ) as enqueue_block:
            result = asyncio.run(enqueue_unknown_block(request))

        self.assertEqual(result, {"queued": True, "block_id": "run-1:3"})
        enqueue_block.assert_called_once_with(
            "run-1:3", "run-1", "unrecognized cli block", {"vendor": "cisco"}
        )


    def test_lookup_vendor_returns_match_within_threshold(self):
        fake_collection = MagicMock()
        fake_collection.query.return_value = {
            "ids": [["seed-cisco"]],
            "distances": [[0.2]],
            "metadatas": [[{"vendor": "cisco", "os": "IOS-XE", "seed": True}]],
        }

        with patch(
            "app.main.get_vendor_fingerprint_collection",
            return_value=fake_collection,
        ):
            result = lookup_vendor(VendorLookupRequest(text="hostname EDGE-RTR\nip ssh version 2"))

        self.assertEqual(result["vendor"], "cisco")
        self.assertEqual(result["os"], "IOS-XE")
        self.assertAlmostEqual(result["confidence"], 0.8)

    def test_lookup_vendor_returns_none_beyond_threshold(self):
        fake_collection = MagicMock()
        fake_collection.query.return_value = {
            "ids": [["seed-cisco"]],
            "distances": [[5.0]],
            "metadatas": [[{"vendor": "cisco", "os": "IOS-XE"}]],
        }

        with patch(
            "app.main.get_vendor_fingerprint_collection",
            return_value=fake_collection,
        ):
            result = lookup_vendor(VendorLookupRequest(text="some unrelated text"))

        self.assertIsNone(result["vendor"])

    def test_lookup_vendor_returns_none_when_collection_is_empty(self):
        fake_collection = MagicMock()
        fake_collection.query.return_value = {"ids": [[]], "distances": [[]], "metadatas": [[]]}

        with patch(
            "app.main.get_vendor_fingerprint_collection",
            return_value=fake_collection,
        ):
            result = lookup_vendor(VendorLookupRequest(text="anything"))

        self.assertIsNone(result["vendor"])

    def test_add_vendor_fingerprint_stores_confirmed_sample(self):
        fake_collection = MagicMock()

        request = VendorFingerprintRequest(
            vendor="fortinet",
            os="FortiOS",
            sample_text="config system global\n    set hostname fw-01\nend",
        )

        with patch(
            "app.main.get_vendor_fingerprint_collection",
            return_value=fake_collection,
        ):
            result = add_vendor_fingerprint(request)

        self.assertEqual(result, {"stored": True, "vendor": "fortinet"})
        fake_collection.upsert.assert_called_once()
        _, kwargs = fake_collection.upsert.call_args
        self.assertEqual(kwargs["metadatas"], [{"vendor": "fortinet", "os": "FortiOS", "seed": False}])


if __name__ == "__main__":
    unittest.main()
