import os
from typing import List
from uuid import uuid4


import chromadb
from . import db
from .embeddings import get_embedding_function
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field


app = FastAPI(title="NetAuditor Learning/RAG Service")


# Configuration
CHROMADB_HOST = os.getenv("CHROMADB_HOST", "chromadb")
CHROMADB_PORT = int(os.getenv("CHROMADB_PORT", "8000"))
RAG_TOP_K = int(os.getenv("RAG_TOP_K", "5"))

# A query further than this from its nearest fingerprint is not a match —
# tune empirically; chromadb's default embedding distance has no fixed
# "this is definitely vendor X" cutoff.
VENDOR_LOOKUP_MAX_DISTANCE = float(os.getenv("VENDOR_LOOKUP_MAX_DISTANCE", "0.8"))

# Bootstrap samples for the 4 vendors vendor_detector.py already recognizes by
# regex. This lets semantic lookup answer something useful from a cold start,
# before any admin has confirmed a real device sample via
# POST /learning/vendor-fingerprints.
_VENDOR_FINGERPRINT_SEEDS = [
    (
        "cisco",
        "IOS-XE",
        "hostname CORE-SW-01\nversion 17.9.3\nservice timestamps debug datetime msec\n"
        "ip ssh version 2\nline vty 0 15\n transport input ssh",
    ),
    (
        "juniper",
        "JunOS",
        "set system host-name edge-fw\nset system services ssh\nset version 21.2R3\n"
        "interfaces {\n    ge-0/0/0 {\n        unit 0;\n    }\n}",
    ),
    (
        "paloalto",
        "PAN-OS",
        "set deviceconfig system hostname pa-fw-01\nset deviceconfig system type static\n"
        "set network interface ethernet1/1\nset deviceconfig system sw-version 10.2.0",
    ),
    (
        "arista",
        "EOS",
        "! Arista EOS device\nhostname spine1\ndaemon TerminAttr\n"
        "management api http-commands\n   no shutdown",
    ),
]


class UnrecognizedBlock(BaseModel):
    block_id: str
    raw_text: str


class UnknownBlockRequest(BaseModel):
    """Intake shape for a config chunk that failed schema validation
    upstream (Parsing) and needs a human mapping. Internal, service-to-service
    — not part of the gateway's route table."""

    block_id: str
    audit_run_id: str
    raw_text: str
    chunk_context: dict = Field(default_factory=dict)


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


def get_vendor_fingerprint_collection():
    """Connect to ChromaDB and return the vendor-fingerprint collection,
    seeding it from _VENDOR_FINGERPRINT_SEEDS on first use so lookups return
    something useful before any admin has confirmed a real sample."""
    client = chromadb.HttpClient(
        host=CHROMADB_HOST,
        port=CHROMADB_PORT,
    )

    collection = client.get_or_create_collection(
        name="vendor_fingerprints",
        embedding_function=get_embedding_function(),
    )

    if collection.count() == 0:
        collection.upsert(
            ids=[f"seed-{vendor}" for vendor, _, _ in _VENDOR_FINGERPRINT_SEEDS],
            documents=[text for _, _, text in _VENDOR_FINGERPRINT_SEEDS],
            metadatas=[
                {"vendor": vendor, "os": os_name, "seed": True}
                for vendor, os_name, _ in _VENDOR_FINGERPRINT_SEEDS
            ],
        )

    return collection


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
    return await db.get_pending_blocks()


@app.post("/learning/queue")
async def enqueue_unknown_block(body: UnknownBlockRequest):
    """
    Queue a config chunk that failed schema validation upstream. Called by
    Parsing (directly or via a future unknown_handler) — not exposed through
    the gateway.
    """
    await db.enqueue_block(body.block_id, body.audit_run_id, body.raw_text, body.chunk_context)
    return {"queued": True, "block_id": body.block_id}


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

    # Best-effort: a mapping confirmed for a block that was never queued (or
    # already resolved) is still a valid mapping — don't fail the request
    # over queue bookkeeping.
    was_queued = await db.mark_mapped(body.block_id)

    return {
        "confirmed": True,
        "block_id": body.block_id,
        "was_queued": was_queued,
    }
class VendorLookupRequest(BaseModel):
    text: str


@app.post("/learning/vendor-lookup")
def lookup_vendor(body: VendorLookupRequest):
    """
    Best-effort semantic vendor guess for a config sample regex detection
    couldn't identify. Called by Parsing only to enrich a human_review
    record (see services/parsing/app/vendor_fingerprint.py) — never to drive
    parsing itself, so a wrong guess here can't produce a bad compliance
    verdict.
    """
    try:
        collection = get_vendor_fingerprint_collection()
        results = collection.query(query_texts=[body.text], n_results=1)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"ChromaDB unavailable: {exc}",
        )

    ids = results.get("ids") or [[]]
    if not ids[0]:
        return {"vendor": None}

    distance = results["distances"][0][0]
    if distance > VENDOR_LOOKUP_MAX_DISTANCE:
        return {"vendor": None}

    metadata = results["metadatas"][0][0]
    return {
        "vendor": metadata.get("vendor"),
        "os": metadata.get("os"),
        "confidence": max(0.0, 1.0 - distance),
        "distance": distance,
    }


class VendorFingerprintRequest(BaseModel):
    vendor: str
    os: str | None = None
    sample_text: str


@app.post("/learning/vendor-fingerprints")
def add_vendor_fingerprint(body: VendorFingerprintRequest):
    """
    Add a human-confirmed vendor sample to the fingerprint collection, so the
    next unrecognized device from the same vendor gets a semantic match
    instead of a bare "unknown". Intended for a future admin/mapping-ui
    action; no caller exists yet.
    """
    try:
        collection = get_vendor_fingerprint_collection()
        fingerprint_id = f"confirmed-{uuid4()}"
        collection.upsert(
            ids=[fingerprint_id],
            documents=[body.sample_text],
            metadatas=[{"vendor": body.vendor, "os": body.os, "seed": False}],
        )
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"ChromaDB unavailable: {exc}",
        )

    return {"stored": True, "vendor": body.vendor}


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
