# Parsing / SLM service

Owner: Parsing / SLM lane (`TEAM_OWNERSHIP.md`)

## Responsibilities

- Detect vendor/OS once at ingestion-job level.
- Parse each fixed-size Ingestion chunk using the established device context.
- Optionally enrich prompts with trusted Learning/RAG examples.
- Generate structured JSON through Ollama and validate it with the shared `services/schema/` package.
- Merge chunk observations deterministically and gate publication on confidence and supported vendor identity.
- Publish only the `compliance.evaluate_baseline` Celery task; Parsing never evaluates compliance itself.

## Standalone development

From the Parsing service directory:

```bash
cd services/parsing
cp .env.example .env
# Install the shared schema package once in the environment.
pip install -e ../schema
USE_MOCK_SLM=true python -m app.worker
```

For Python package setup:

```bash
cd services/schema && pip install -e .
cd ../parsing
pip install -r requirements.txt
pip install -r requirements-dev.txt
pytest -q
```

## Docker

The Parsing image is built from the repository root so it can install the shared schema package:

```bash
docker compose build parsing
docker compose up parsing ollama chromadb redis
```

The Parsing service depends on Redis because it both consumes `parsing.process_config` and publishes `compliance.evaluate_baseline`.

## Ollama structured output

`GRAMMAR_ENGINE=outlines` is retained for configuration compatibility with the architecture documents. The current implementation does not import Outlines to control a remote Ollama decoder. Instead, it sends the shared JSON Schema through Ollama's `format` parameter and always performs Pydantic validation afterward.

## RAG

RAG is an injectable optional provider. The default provider returns an empty context, so Parsing remains runnable when Learning/ChromaDB is unavailable. Parsing does not implement the Learning lane.
