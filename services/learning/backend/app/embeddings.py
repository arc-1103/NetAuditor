import os

from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction


MODEL_NAME = os.getenv(
    "EMBEDDING_MODEL",
    "sentence-transformers/all-MiniLM-L6-v2",
)


def get_embedding_function():
    return SentenceTransformerEmbeddingFunction(
        model_name=MODEL_NAME
    )
