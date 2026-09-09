
# Learning / RAG Service

Owner: Sanjeevani

## Overview

The Learning/RAG service stores confirmed network configuration mappings
and retrieves previously learned mappings using semantic similarity.

## Technology

- FastAPI
- ChromaDB
- SentenceTransformers
- BAAI/bge-small-en-v1.5 embeddings (override via `EMBEDDING_MODEL`)
- Docker

## API

### Health

`GET /health`

Returns the service health status.

### Learning Queue

`GET /learning/queue`

Returns unrecognized configuration blocks awaiting mapping.

### Store Mapping

`POST /learning/map`

Stores a confirmed mapping in ChromaDB.

Example:

```json
{
  "block_id": "demo-1",
  "cli_pattern": "crypto isakmp policy 10 / hash sha256",
  "field": "crypto.ike.hash_algorithm",
  "value": "SHA256"
}
```

### Baseline Vectors (unsupervised anomaly detection)

`POST /learning/baseline-vectors` — embeds and stores one evaluated
baseline, keyed by `config_sha256` and tagged `[vendor, os]`. Called by
`services/compliance/app/anomaly_client.py` for every evaluated device.

`POST /learning/baseline-vectors/anomaly-check` — fits an `IsolationForest`
on the device's vendor+OS peer cohort (excluding itself) and scores it as a
held-out point. Returns `{"status": "insufficient_peers", "peer_count": N}`
below `ANOMALY_MIN_PEER_COUNT` (default 5) peers, otherwise
`{"status": "scored", "is_anomaly": bool, "anomaly_score": float,
"peer_count": N}`. This is a statistical signal Compliance surfaces
separately from its deterministic verdict — see
`services/compliance/README.md`'s Unsupervised Semantic Anomaly Detection
section.
