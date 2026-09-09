
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
