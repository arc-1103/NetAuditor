import os
from typing import List


import chromadb
from .embeddings import get_embedding_function
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel


app = FastAPI(title="NetAuditor Learning/RAG Service")


# Configuration
CHROMADB_HOST = os.getenv("CHROMADB_HOST", "chromadb")
CHROMADB_PORT = int(os.getenv("CHROMADB_PORT", "8000"))
RAG_TOP_K = int(os.getenv("RAG_TOP_K", "5"))


# Temporary queue.
# Later this will be connected to the Parsing lane.
learning_queue = []


class UnrecognizedBlock(BaseModel):
    block_id: str
    raw_text: str


class LearningMapRequest(BaseModel):
    block_id: str
    cli_pattern: str
    field: str
    value: str


def get_collection():
    """Connect to ChromaDB and return the learning collection."""
    client = chromadb.HttpClient(
        host=CHROMADB_HOST,
        port=CHROMADB_PORT,
    )

    return client.get_or_create_collection(
    name="network_mappings",
    embedding_function=get_embedding_function(),
)


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "learning",
    }


@app.get("/learning/queue", response_model=List[UnrecognizedBlock])
async def get_learning_queue():
    """
    Return network configuration blocks that need human mapping.
    """
    return learning_queue


@app.post("/learning/map")
async def submit_learning_map(
    body: LearningMapRequest,
    x_user_id: str | None = Header(default=None),
):
    """
    Store a confirmed CLI-to-security-field mapping.

    The confirmed mapping becomes knowledge that can later
    be retrieved by the RAG system.
    """

    if not x_user_id:
        raise HTTPException(
            status_code=400,
            detail="X-User-Id header is required",
        )

    try:
        collection = get_collection()

        document = (
            f"CLI pattern: {body.cli_pattern}\n"
            f"Security field: {body.field}\n"
            f"Value: {body.value}"
        )

        metadata = {
            "block_id": body.block_id,
            "cli_pattern": body.cli_pattern,
            "field": body.field,
            "value": body.value,
            "confirmed_by": x_user_id,
        }

        collection.upsert(
            ids=[body.block_id],
            documents=[document],
            metadatas=[metadata],
        )

    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"ChromaDB unavailable: {exc}",
        )

    return {
        "confirmed": True,
        "block_id": body.block_id,
    }
class RAGSearchRequest(BaseModel):
    query: str


@app.post("/learning/search")
def search_learning(body: RAGSearchRequest):
    try:
        collection = get_collection()

        results = collection.query(
            query_texts=[body.query],
            n_results=RAG_TOP_K,
        )

        return {
            "query": body.query,
            "results": results,
        }

    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"ChromaDB unavailable: {exc}",
        )
