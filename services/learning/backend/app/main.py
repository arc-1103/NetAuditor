import os
from typing import List
from uuid import uuid4


import chromadb
from . import db
from .embeddings import get_embedding_function
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from sklearn.ensemble import IsolationForest


app = FastAPI(title="NetAuditor Learning/RAG Service")


# Configuration
CHROMADB_HOST = os.getenv("CHROMADB_HOST", "chromadb")
CHROMADB_PORT = int(os.getenv("CHROMADB_PORT", "8000"))
RAG_TOP_K = int(os.getenv("RAG_TOP_K", "5"))

_chroma_client = None


def _get_chroma_client():
    """A fresh chromadb.HttpClient() does a tenant/database handshake over
    HTTP on construction — building one per request (as every endpoint
    below used to) meant every single call paid that round trip on top of
    its actual query. One client, reused for the life of the process."""
    global _chroma_client
    if _chroma_client is None:
        _chroma_client = chromadb.HttpClient(host=CHROMADB_HOST, port=CHROMADB_PORT)
    return _chroma_client

# Below this many peers, an IsolationForest fit isn't statistically
# meaningful — see check_baseline_anomaly.
ANOMALY_MIN_PEER_COUNT = int(os.getenv("ANOMALY_MIN_PEER_COUNT", "5"))

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
    # Defaults to "unknown", matching device_context's own convention
    # elsewhere in this codebase — never stored as None (see UNKNOWN_OS
    # below for why). Confirmed mappings are now tagged so search_learning
    # can pre-filter by vendor/OS instead of searching every vendor's
    # mappings at once — retrieving a Juniper mapping for a Cisco chunk was
    # a real, live bug.
    vendor: str = "unknown"
    os: str | None = None


def get_collection():
    """Connect to ChromaDB and return the learning collection."""
    return _get_chroma_client().get_or_create_collection(
        name="network_mappings",
        embedding_function=get_embedding_function(),
    )


def get_remediation_manual_collection():
    """Connect to ChromaDB and return the remediation-manual collection.

    Indexed by [vendor, os, control_id] (a Rule ID's remediation steps
    either apply to a given vendor/OS or they don't), so lookups use an
    exact metadata filter, not embedding similarity — see
    search_remediation_manual. No cold-start seeds: unlike vendor
    fingerprints, a fabricated vendor-manual excerpt would be actively
    misleading grounding for CLI synthesis, so this starts genuinely empty
    until an admin adds real excerpts.
    """
    return _get_chroma_client().get_or_create_collection(
        name="remediation_manuals",
        embedding_function=get_embedding_function(),
    )


# Sentinel for a missing OS, same reasoning as remediation manuals' ANY_OS:
# ChromaDB rejects a None metadata value outright, and grouping by "unknown"
# is itself a meaningful peer cohort (devices of a vendor nobody has
# identified the OS for yet), not a null case to special-case away.
UNKNOWN_OS = "unknown"


def get_baseline_vector_collection():
    """Connect to ChromaDB and return the baseline-vector collection for
    unsupervised semantic anomaly detection (see check_baseline_anomaly).

    One embedding per device, keyed by config_sha256, tagged with
    [vendor, os] for peer-cohort grouping. Unlike the RAG/remediation-manual
    collections, embeddings here are compared to each other directly (via
    IsolationForest), not retrieved by nearest-neighbor search, so no
    metadata filter shape is baked in beyond the plain vendor+os equality
    check_baseline_anomaly already does.
    """
    return _get_chroma_client().get_or_create_collection(
        name="baseline_vectors",
        embedding_function=get_embedding_function(),
    )


# Device-identity fields excluded from the embedded text: they identify
# WHICH device this is, not WHAT its configuration says, so including them
# would make embedding similarity partly about hostnames/hashes rather than
# security-setting content — the opposite of what a peer-cohort comparison
# needs.
_DEVICE_FIELDS_EXCLUDED_FROM_ANOMALY_TEXT = {
    "raw_hostname", "config_sha256", "parsing_confidence", "unknown_blocks_count",
    "detected_vendor", "detected_os", "detected_os_version", "detected_hardware_model",
}


def flatten_baseline_for_embedding(baseline: dict) -> str:
    """Render a normalized SecurityBaseline as deterministic, order-
    independent text for embedding. The schema is already vendor-neutral
    (canonical fields like ssh.version, telnet.enabled), so this text
    captures configuration semantics, not vendor CLI syntax."""
    lines: list[str] = []

    def _walk(prefix: str, value) -> None:
        if isinstance(value, dict):
            for key, val in sorted(value.items()):
                if prefix == "device" and key in _DEVICE_FIELDS_EXCLUDED_FROM_ANOMALY_TEXT:
                    continue
                _walk(f"{prefix}.{key}" if prefix else key, val)
        elif isinstance(value, list):
            for item in sorted(value, key=str):
                _walk(prefix, item)
        else:
            lines.append(f"{prefix}={value}")

    _walk("", baseline)
    return "\n".join(sorted(lines))


def get_vendor_fingerprint_collection():
    """Connect to ChromaDB and return the vendor-fingerprint collection,
    seeding it from _VENDOR_FINGERPRINT_SEEDS on first use so lookups return
    something useful before any admin has confirmed a real sample."""
    collection = _get_chroma_client().get_or_create_collection(
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
            "vendor": body.vendor,
            "os": body.os or UNKNOWN_OS,
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


class RemediationManualRequest(BaseModel):
    vendor: str
    os: str | None = None
    control_id: str
    manual_excerpt: str


#: Sentinel stored in place of a missing `os`, never `None` — ChromaDB
#: rejects `None` metadata values outright, and a stored `None` could never
#: be matched by search_remediation_manual's `$in` filter below anyway.
#: An excerpt tagged "any" is vendor-wide, OS-agnostic guidance.
ANY_OS = "any"


@app.post("/learning/remediation-manuals")
def add_remediation_manual(body: RemediationManualRequest):
    """
    Add a vendor remediation-manual excerpt for one control, so the agentic
    RAG remediation fallback (services/remediation/app/rag_remediation.py)
    has grounded context to synthesize CLI from for a vendor with no
    committed .j2 template. Intended for an admin/mapping-ui action; no
    caller exists yet.
    """
    os_key = body.os or ANY_OS
    try:
        collection = get_remediation_manual_collection()
        manual_id = f"{body.vendor}:{os_key}:{body.control_id}"
        collection.upsert(
            ids=[manual_id],
            documents=[body.manual_excerpt],
            metadatas=[{"vendor": body.vendor, "os": os_key, "control_id": body.control_id}],
        )
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"ChromaDB unavailable: {exc}",
        )

    return {"stored": True, "manual_id": manual_id}


class RemediationManualLookupRequest(BaseModel):
    vendor: str
    os: str | None = None
    control_id: str


@app.post("/learning/remediation-manuals/search")
def search_remediation_manual(body: RemediationManualLookupRequest):
    """
    Exact-match lookup by [control_id + vendor + OS] — a Rule ID's
    remediation steps either apply to this exact vendor/OS or they don't, so
    this is a structured index lookup, not a fuzzy embedding search (a close
    but wrong embedding match would be actively dangerous grounding for CLI
    synthesis). Called only by Remediation's agentic RAG fallback, for
    findings with no committed .j2 template.

    OS matching has two tiers, never a wildcard: a lookup for a known OS
    matches excerpts tagged for that exact OS, plus any OS-agnostic ("any")
    excerpt for the vendor — general guidance still applies. A lookup with
    no known OS matches only "any"-tagged excerpts: an OS-specific excerpt
    written for a *different* OS must never be handed to the SLM as if it
    applied here just because the caller didn't know which OS this device
    runs.
    """
    os_values = [body.os, ANY_OS] if body.os else [ANY_OS]
    where = {
        "$and": [
            {"vendor": body.vendor},
            {"control_id": body.control_id},
            {"os": {"$in": os_values}},
        ]
    }

    try:
        collection = get_remediation_manual_collection()
        results = collection.get(where=where)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"ChromaDB unavailable: {exc}",
        )

    documents = results.get("documents") or []
    return {"found": bool(documents), "manual_excerpts": documents}


class RAGSearchRequest(BaseModel):
    query: str
    vendor: str | None = None
    os: str | None = None


@app.post("/learning/search")
def search_learning(body: RAGSearchRequest):
    # Never an open-ended search across every vendor's confirmed mappings
    # at once — pre-filter before similarity search runs, same principle
    # remediation-manual lookup and anomaly-cohort selection already apply.
    # No vendor known (an old caller, or a genuinely unclassified device)
    # is the one case left unfiltered.
    where = None
    if body.vendor:
        os_values = [body.os, UNKNOWN_OS] if body.os else [UNKNOWN_OS]
        where = {"$and": [{"vendor": body.vendor}, {"os": {"$in": os_values}}]}

    try:
        collection = get_collection()

        results = collection.query(
            query_texts=[body.query],
            n_results=RAG_TOP_K,
            where=where,
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


class BaselineVectorRequest(BaseModel):
    config_sha256: str
    vendor: str
    os: str | None = None
    baseline: dict = Field(default_factory=dict)


@app.post("/learning/baseline-vectors")
def ingest_baseline_vector(body: BaselineVectorRequest):
    """
    Embed and store one evaluated baseline for unsupervised semantic anomaly
    detection (services/compliance/app/anomaly_client.py). Called for every
    evaluated device, findings or not — a clean device is still a legitimate
    peer for its vendor+OS cohort. Upserting by config_sha256 means
    re-evaluating the same config updates its vector in place rather than
    accumulating duplicates.
    """
    try:
        collection = get_baseline_vector_collection()
        collection.upsert(
            ids=[body.config_sha256],
            documents=[flatten_baseline_for_embedding(body.baseline)],
            metadatas=[{"vendor": body.vendor, "os": body.os or UNKNOWN_OS}],
        )
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"ChromaDB unavailable: {exc}",
        )

    return {"stored": True}


class AnomalyCheckRequest(BaseModel):
    config_sha256: str
    vendor: str
    os: str | None = None


@app.post("/learning/baseline-vectors/anomaly-check")
def check_baseline_anomaly(body: AnomalyCheckRequest):
    """
    Flag "configuration drift": is this device's embedding an outlier
    relative to its vendor+OS peer cohort's embeddings?

    Fits an IsolationForest on the peer cohort ALONE (this device excluded),
    then scores this device as a held-out point — the peers define what
    "normal" looks like; the target is never part of its own reference set.
    Below ANOMALY_MIN_PEER_COUNT peers, a fit isn't statistically
    meaningful, so this returns "insufficient_peers" rather than a
    fabricated verdict — the same reasoning vendor_fingerprint.py's distance
    cutoff and remediation-manual matching apply to their own confidence
    signals.

    Called only by services/compliance/app/anomaly_client.py, after the
    target baseline has already been ingested via
    POST /learning/baseline-vectors. Not called by any compliance verdict
    logic: this is a statistical signal attached alongside a finding, never
    folded into it — see services/compliance/README.md's Unsupervised
    Anomaly Detection section for why.
    """
    try:
        collection = get_baseline_vector_collection()
        target = collection.get(ids=[body.config_sha256], include=["embeddings"])
        target_embeddings = target.get("embeddings")
        if target_embeddings is None or len(target_embeddings) == 0:
            return {"status": "not_ingested"}

        peers = collection.get(
            where={"$and": [{"vendor": body.vendor}, {"os": body.os or UNKNOWN_OS}]},
            include=["embeddings"],
        )
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"ChromaDB unavailable: {exc}",
        )

    peer_ids = peers.get("ids") or []
    peer_embeddings = [
        embedding
        for peer_id, embedding in zip(peer_ids, peers.get("embeddings") or [])
        if peer_id != body.config_sha256
    ]

    if len(peer_embeddings) < ANOMALY_MIN_PEER_COUNT:
        return {"status": "insufficient_peers", "peer_count": len(peer_embeddings)}

    forest = IsolationForest(contamination="auto", random_state=42)
    forest.fit(peer_embeddings)
    target_embedding = target_embeddings[0]
    is_anomaly = bool(forest.predict([target_embedding])[0] == -1)
    anomaly_score = float(forest.score_samples([target_embedding])[0])

    return {
        "status": "scored",
        "is_anomaly": is_anomaly,
        "anomaly_score": anomaly_score,
        "peer_count": len(peer_embeddings),
    }
