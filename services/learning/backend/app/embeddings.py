import os

from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction

# BAAI/bge-small-en-v1.5: 33M params, 384-dim (same width as the old
# all-MiniLM-L6-v2 default, so an existing ChromaDB collection keeps working
# without a dimension mismatch), runs on CPU or <400MB VRAM, and benchmarks
# well on short, dense technical text — the shape of a CLI config line or a
# CIS control mapping. Swap to another sentence-transformers model (e.g.
# Snowflake/snowflake-arctic-embed-m) via EMBEDDING_MODEL; note that model is
# 768-dim, so switching to it requires recreating any existing collection.
MODEL_NAME = os.getenv(
    "EMBEDDING_MODEL",
    "BAAI/bge-small-en-v1.5",
)


def get_embedding_function():
    return SentenceTransformerEmbeddingFunction(
        model_name=MODEL_NAME
    )
