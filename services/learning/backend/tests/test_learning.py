import asyncio
import unittest
from unittest.mock import MagicMock, patch

from app.main import (
    AnomalyCheckRequest,
    BaselineVectorRequest,
    LearningMapRequest,
    RAGSearchRequest,
    RemediationManualLookupRequest,
    RemediationManualRequest,
    UnknownBlockRequest,
    UnrecognizedBlock,
    VendorFingerprintRequest,
    VendorLookupRequest,
    add_remediation_manual,
    add_vendor_fingerprint,
    check_baseline_anomaly,
    enqueue_unknown_block,
    flatten_baseline_for_embedding,
    get_learning_queue,
    health,
    ingest_baseline_vector,
    lookup_vendor,
    search_learning,
    search_remediation_manual,
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

    def test_add_remediation_manual_stores_excerpt(self):
        fake_collection = MagicMock()

        request = RemediationManualRequest(
            vendor="fortinet",
            os="FortiOS",
            control_id="CIS-FORTI-1.1.1",
            manual_excerpt="config system global\n    set admin-ssh-v1 disable\nend",
        )

        with patch(
            "app.main.get_remediation_manual_collection",
            return_value=fake_collection,
        ):
            result = add_remediation_manual(request)

        self.assertTrue(result["stored"])
        self.assertEqual(result["manual_id"], "fortinet:FortiOS:CIS-FORTI-1.1.1")
        fake_collection.upsert.assert_called_once()
        _, kwargs = fake_collection.upsert.call_args
        self.assertEqual(
            kwargs["metadatas"],
            [{"vendor": "fortinet", "os": "FortiOS", "control_id": "CIS-FORTI-1.1.1"}],
        )

    def test_search_remediation_manual_returns_exact_matches(self):
        fake_collection = MagicMock()
        fake_collection.get.return_value = {
            "documents": ["config system global\n    set admin-ssh-v1 disable\nend"],
        }

        request = RemediationManualLookupRequest(vendor="fortinet", os="FortiOS", control_id="CIS-FORTI-1.1.1")

        with patch(
            "app.main.get_remediation_manual_collection",
            return_value=fake_collection,
        ):
            result = search_remediation_manual(request)

        self.assertTrue(result["found"])
        self.assertEqual(len(result["manual_excerpts"]), 1)
        # A known-OS lookup matches that exact OS plus vendor-wide ("any")
        # guidance — never a wildcard match against every OS.
        fake_collection.get.assert_called_once_with(
            where={
                "$and": [
                    {"vendor": "fortinet"},
                    {"control_id": "CIS-FORTI-1.1.1"},
                    {"os": {"$in": ["FortiOS", "any"]}},
                ]
            }
        )

    def test_search_remediation_manual_with_unknown_os_only_matches_any_tagged_excerpts(self):
        """An OS-specific excerpt written for a *different* OS must never be
        handed to the SLM just because this lookup didn't know its OS."""
        fake_collection = MagicMock()
        fake_collection.get.return_value = {"documents": []}

        request = RemediationManualLookupRequest(vendor="cisco", control_id="CIS-IOS-9.9.9")

        with patch(
            "app.main.get_remediation_manual_collection",
            return_value=fake_collection,
        ):
            result = search_remediation_manual(request)

        self.assertFalse(result["found"])
        self.assertEqual(result["manual_excerpts"], [])
        fake_collection.get.assert_called_once_with(
            where={
                "$and": [
                    {"vendor": "cisco"},
                    {"control_id": "CIS-IOS-9.9.9"},
                    {"os": {"$in": ["any"]}},
                ]
            }
        )

    def test_add_remediation_manual_defaults_os_to_any_sentinel_never_none(self):
        """ChromaDB rejects a None metadata value outright, and a stored
        None could never be matched by search's $in filter anyway."""
        fake_collection = MagicMock()

        request = RemediationManualRequest(
            vendor="cisco", control_id="CIS-IOS-1.1.1", manual_excerpt="general guidance",
        )

        with patch(
            "app.main.get_remediation_manual_collection",
            return_value=fake_collection,
        ):
            result = add_remediation_manual(request)

        self.assertEqual(result["manual_id"], "cisco:any:CIS-IOS-1.1.1")
        _, kwargs = fake_collection.upsert.call_args
        self.assertEqual(
            kwargs["metadatas"],
            [{"vendor": "cisco", "os": "any", "control_id": "CIS-IOS-1.1.1"}],
        )

    # ── Unsupervised semantic anomaly detection ──────────────────────
    def test_flatten_baseline_for_embedding_excludes_device_identity_fields(self):
        baseline = {
            "device": {
                "raw_hostname": "EDGE-RTR",
                "config_sha256": "a" * 64,
                "parsing_confidence": 0.9,
                "detected_vendor": "cisco",
            },
            "ssh": {"enabled": True, "version": "2"},
        }
        text = flatten_baseline_for_embedding(baseline)

        self.assertIn("ssh.enabled=True", text)
        self.assertIn("ssh.version=2", text)
        self.assertNotIn("EDGE-RTR", text)
        self.assertNotIn("a" * 64, text)
        self.assertNotIn("cisco", text)

    def test_flatten_baseline_for_embedding_is_order_independent(self):
        a = {"ssh": {"enabled": True, "version": "2"}, "telnet": {"enabled": "DISABLED"}}
        b = {"telnet": {"enabled": "DISABLED"}, "ssh": {"version": "2", "enabled": True}}
        self.assertEqual(flatten_baseline_for_embedding(a), flatten_baseline_for_embedding(b))

    def test_ingest_baseline_vector_stores_flattened_embedding(self):
        fake_collection = MagicMock()
        request = BaselineVectorRequest(
            config_sha256="a" * 64,
            vendor="cisco",
            os="IOS-XE",
            baseline={"ssh": {"enabled": True, "version": "2"}},
        )

        with patch("app.main.get_baseline_vector_collection", return_value=fake_collection):
            result = ingest_baseline_vector(request)

        self.assertTrue(result["stored"])
        _, kwargs = fake_collection.upsert.call_args
        self.assertEqual(kwargs["ids"], ["a" * 64])
        self.assertEqual(kwargs["metadatas"], [{"vendor": "cisco", "os": "IOS-XE"}])
        self.assertIn("ssh.enabled=True", kwargs["documents"][0])

    def test_ingest_baseline_vector_defaults_os_to_unknown_sentinel(self):
        fake_collection = MagicMock()
        request = BaselineVectorRequest(config_sha256="b" * 64, vendor="cisco", baseline={})

        with patch("app.main.get_baseline_vector_collection", return_value=fake_collection):
            ingest_baseline_vector(request)

        _, kwargs = fake_collection.upsert.call_args
        self.assertEqual(kwargs["metadatas"], [{"vendor": "cisco", "os": "unknown"}])

    class _FakeVectorCollection:
        def __init__(self, target_embedding=None, peer_ids=None, peer_embeddings=None):
            self.target_embedding = target_embedding
            self.peer_ids = peer_ids or []
            self.peer_embeddings = peer_embeddings or []

        def get(self, ids=None, where=None, include=None):
            if ids is not None:
                if self.target_embedding is None:
                    return {"ids": [], "embeddings": []}
                return {"ids": ids, "embeddings": [self.target_embedding]}
            return {"ids": self.peer_ids, "embeddings": self.peer_embeddings}

    def test_anomaly_check_returns_not_ingested_when_target_is_missing(self):
        fake_collection = self._FakeVectorCollection(target_embedding=None)
        request = AnomalyCheckRequest(config_sha256="a" * 64, vendor="cisco", os="IOS-XE")

        with patch("app.main.get_baseline_vector_collection", return_value=fake_collection):
            result = check_baseline_anomaly(request)

        self.assertEqual(result, {"status": "not_ingested"})

    def test_anomaly_check_returns_insufficient_peers_below_threshold(self):
        fake_collection = self._FakeVectorCollection(
            target_embedding=[0.0, 0.0],
            peer_ids=["p1", "p2"],
            peer_embeddings=[[0.0, 0.0], [0.1, 0.1]],
        )
        request = AnomalyCheckRequest(config_sha256="a" * 64, vendor="cisco", os="IOS-XE")

        with patch("app.main.get_baseline_vector_collection", return_value=fake_collection):
            result = check_baseline_anomaly(request)

        self.assertEqual(result["status"], "insufficient_peers")
        self.assertEqual(result["peer_count"], 2)

    def test_anomaly_check_excludes_the_target_from_its_own_peer_count(self):
        """The target's own vector matches its own vendor+os where clause —
        it must not count itself as a peer."""
        peer_ids = [f"peer-{i}" for i in range(6)]
        peer_embeddings = [[0.0, 0.0]] * 6
        fake_collection = self._FakeVectorCollection(
            target_embedding=[0.0, 0.0],
            peer_ids=["target-id", *peer_ids],
            peer_embeddings=[[0.0, 0.0], *peer_embeddings],
        )
        request = AnomalyCheckRequest(config_sha256="target-id", vendor="cisco", os="IOS-XE")

        with patch("app.main.get_baseline_vector_collection", return_value=fake_collection):
            result = check_baseline_anomaly(request)

        self.assertEqual(result["status"], "scored")
        self.assertEqual(result["peer_count"], 6)

    def test_anomaly_check_scores_a_clear_outlier_lower_than_a_typical_point(self):
        """score_samples: lower means more anomalous. A point far outside a
        tight peer cluster must score lower than a point at the cluster's
        center, regardless of exactly where IsolationForest's predict()
        threshold falls for this sample size."""
        peer_embeddings = [[0.0, 0.0], [0.1, 0.0], [0.0, 0.1], [-0.1, 0.0], [0.0, -0.1], [0.05, 0.05]]
        peer_ids = [f"peer-{i}" for i in range(len(peer_embeddings))]

        def _score_for(target_embedding):
            fake_collection = self._FakeVectorCollection(
                target_embedding=target_embedding, peer_ids=peer_ids, peer_embeddings=peer_embeddings
            )
            request = AnomalyCheckRequest(config_sha256="target-id", vendor="cisco", os="IOS-XE")
            with patch("app.main.get_baseline_vector_collection", return_value=fake_collection):
                return check_baseline_anomaly(request)

        typical = _score_for([0.0, 0.0])
        outlier = _score_for([1000.0, 1000.0])

        self.assertEqual(typical["status"], "scored")
        self.assertEqual(outlier["status"], "scored")
        self.assertLess(outlier["anomaly_score"], typical["anomaly_score"])
        self.assertTrue(outlier["is_anomaly"])


if __name__ == "__main__":
    unittest.main()
