# Local LLM Setup (Ollama)

NetAuditor uses a local LLM served by [Ollama](https://ollama.com) for two
things only — it is never on the compliance verdict path:

| Service | Where | Purpose |
|---|---|---|
| `parsing` | `app/slm_client.py` | Per-chunk CLI → normalized-JSON extraction, with structured output enforced via Ollama's `format` JSON-schema field. |
| `remediation` | `app/rag_remediation.py` | Agentic-RAG fallback that drafts a CLI fix only when a finding's vendor has no committed Jinja2 template. Every other remediation stays on the deterministic `template_engine.py` path. |

Both services default to model **`qwen2.5:7b-instruct-q4_K_M`** (Qwen2.5
Instruct 7B, int4/Q4_K_M quantized) and talk to Ollama over
plain HTTP — there's no client library dependency, no API key, and nothing to
authenticate.

---

## 1. Running Ollama

### Option A — via docker-compose (default, recommended)

The `ollama` service is already declared in the root `docker-compose.yml` and
is on the shared `audit-net` network. Nothing to configure — just bring up
the stack:

```bash
docker compose up ollama
# or as part of the full stack:
docker compose up --build
```

Services reach it at `http://ollama:11434` (the container DNS name), which is
already the default in every `.env.example` that needs it.

### Option B — standalone Ollama on the host

If you'd rather run Ollama natively (e.g. to use a GPU without exposing it
into Docker), install it from https://ollama.com/download, start it, then
point each service's `.env` at your host instead of the container:

```
OLLAMA_HOST=http://host.docker.internal:11434   # from inside Docker
# or, if running the service outside Docker too:
OLLAMA_HOST=http://localhost:11434
```

## 2. Pulling the model

Ollama does not ship models — pull it once before your first real (non-mock)
run:

```bash
# via the docker-compose container:
docker compose exec ollama ollama pull qwen2.5:7b-instruct-q4_K_M

# or, if running Ollama natively:
ollama pull qwen2.5:7b-instruct-q4_K_M
```

`qwen2.5:7b-instruct-q4_K_M` is a ~4.7 GB download. Any Ollama-supported model works —
override it per service with `OLLAMA_MODEL` in that service's `.env` if you
pull something else, but keep `parsing` and `remediation` in sync unless you
have a specific reason not to (both currently default to the same model).

## 3. Relevant environment variables

Set per-service in `services/parsing/.env` and `services/remediation/.env`
(copied from their `.env.example` files):

| Var | Default | Notes |
|---|---|---|
| `OLLAMA_HOST` | `http://ollama:11434` | Base URL Ollama's HTTP API is served on. |
| `OLLAMA_MODEL` | `qwen2.5:7b-instruct-q4_K_M` | Model tag, must already be pulled. |
| `OLLAMA_TIMEOUT_SECONDS` | `60` (parsing only) | Per-request timeout to Ollama. |
| `USE_MOCK_SLM` | `true` (parsing) / `false` (remediation) | See §4. |

## 4. Mock mode vs. real Ollama

Both services can run without a real Ollama for local dev — but the mock
behaves differently in each, so the defaults are intentionally different:

- **`parsing`** (`USE_MOCK_SLM=true` by default): the mock still runs the
  full parse → normalize → validate → merge → confidence/gate pipeline, just
  with a synthesized model response instead of a real one. Safe default —
  you can develop/test the whole parsing lane with zero Ollama setup.
- **`remediation`** (`USE_MOCK_SLM=false` by default): the mock returns a
  fixed placeholder CLI string regardless of the finding. Persisting that as
  a real operator-facing remediation proposal in the default stack would be
  actively misleading, so it's off by default — an unconfigured Ollama makes
  the agentic-RAG fallback request fail with `502` instead of silently
  producing fake CLI. Only set it to `true` for local dev/tests where you
  know the output is a placeholder.

To exercise the real model end-to-end, set `USE_MOCK_SLM=false` in
`services/parsing/.env` (remediation is already `false`), make sure Ollama is
running with the model pulled, then re-run `docker compose up --build`.

## 5. Verifying it works

```bash
# Confirm Ollama is up and the model is present:
curl http://localhost:11434/api/tags

# from inside the compose network, e.g. exec into the parsing container:
docker compose exec parsing curl http://ollama:11434/api/tags
```

If `parsing` or `remediation` can't reach Ollama, both services degrade
gracefully per the project's "optional enrichment degrades, never fails"
rule where applicable — but the SLM call itself is not optional enrichment,
so a genuinely unreachable Ollama with mocks off will surface as a failed
job (parsing → chunk routed to human review or job error; remediation →
`502` on the agentic-RAG fallback request), not a silent bad result.

## 6. Troubleshooting

- **`model not found`** — you forgot to `ollama pull <model>` for the tag in
  `OLLAMA_MODEL`, or pulled it into a different Ollama instance than the one
  `OLLAMA_HOST` points at.
- **Timeouts on first request** — the first call after a pull/restart loads
  the model into memory and is slower; increase `OLLAMA_TIMEOUT_SECONDS` if
  needed rather than assuming Ollama is down.
- **No GPU / slow on CPU** — `qwen2.5:7b-instruct-q4_K_M` runs on CPU but is
  noticeably slower; for a quick smoke test prefer mock mode (§4) and only
  switch on the real model when you actually need real extraction/CLI
  quality.
