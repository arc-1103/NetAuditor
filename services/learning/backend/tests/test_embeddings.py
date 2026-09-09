import importlib
import os
import unittest
from unittest.mock import patch

from app import embeddings


class TestEmbeddings(unittest.TestCase):

    def tearDown(self):
        # Other tests import `app.embeddings` too; leave the module as the
        # default-config version so a later test doesn't see our override.
        importlib.reload(embeddings)

    def test_default_model_is_bge_small(self):
        self.assertEqual(embeddings.MODEL_NAME, "BAAI/bge-small-en-v1.5")

    def test_get_embedding_function_uses_configured_model(self):
        with patch("app.embeddings.SentenceTransformerEmbeddingFunction") as fake_ef:
            embeddings.get_embedding_function()

        fake_ef.assert_called_once_with(model_name="BAAI/bge-small-en-v1.5")

    def test_embedding_model_env_override(self):
        with patch.dict(os.environ, {"EMBEDDING_MODEL": "Snowflake/snowflake-arctic-embed-m"}):
            importlib.reload(embeddings)
            self.assertEqual(embeddings.MODEL_NAME, "Snowflake/snowflake-arctic-embed-m")


if __name__ == "__main__":
    unittest.main()
