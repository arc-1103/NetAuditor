import sys
import types

sys.modules.setdefault("chromadb", types.ModuleType("chromadb"))
sys.modules.setdefault("chromadb.utils", types.ModuleType("chromadb.utils"))
ef = types.ModuleType("chromadb.utils.embedding_functions")
ef.SentenceTransformerEmbeddingFunction = object
sys.modules.setdefault("chromadb.utils.embedding_functions", ef)

from app.embeddings import embedding_text  # noqa: E402


def test_parent_headers_lead_the_embedded_text():
    block = {"raw_text": "interface Gi0/1\n ip access-group X in", "chunk_context": {"sections": ["interface Gi0/1"]}}
    assert embedding_text(block).startswith("Context: interface Gi0/1\ninterface Gi0/1")


def test_no_sections_leaves_text_unchanged():
    assert embedding_text({"raw_text": "abc", "chunk_context": {}}) == "abc"
    assert embedding_text({"raw_text": "abc"}) == "abc"
