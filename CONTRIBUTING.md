# Contributing / Local Dev Workflow

## Why this structure exists
Six people cannot all run the full Docker stack (Ollama + Batfish + OPA +
Postgres + Chroma + MinIO) on a laptop and expect fast iteration. So:

1. **Every service is independently runnable.** Each `services/<lane>/`
   has its own `.env.example`, `Dockerfile`, and `requirements.txt`.
   Copy `.env.example` -> `.env` inside your service folder and you can
   run/test it alone.
2. **Mock flags exist so you don't wait on someone else's container.**
   `USE_MOCK_SLM=true` (parsing), `USE_MOCK_BATFISH=true` (remediation),
   `NEXT_PUBLIC_USE_MOCK_API=true` (frontend). Turn these off only when
   you're doing integration testing against the real stack.
3. **The schema is the contract, and it's versioned.** `services/schema/`
   is the ONLY place `SecurityBaseline` and its sub-models live. If your
   lane needs a new field, you edit `services/schema/`, bump
   `SCHEMA_PACKAGE_VERSION` in `services/parsing/.env.example`, and post
   in the team channel — this is the one file everyone depends on, so
   treat it like a public API, not a scratchpad.
4. **API shapes between services live in `contracts/`, not in someone's
   head.** Before you start a lane, check `contracts/` for the JSON
   shape you'll receive/send. If it's not there yet, propose it there
   first — don't guess and integrate blind on demo day.

## Branch naming
`<lane>/<short-description>` e.g. `parsing/grammar-constrained-decoding`,
`frontend/learning-queue-view`

## Before opening a PR
- [ ] Runs standalone with mocks on (`docker compose up <your-service>`)
- [ ] Didn't touch another lane's folder without a heads-up
- [ ] If you touched `services/schema/` or `contracts/`, you tagged all
      other lane owners in the PR description

## Running the full stack (integration day only)
```
cp .env.example .env
for d in services/*/; do cp "$d/.env.example" "$d/.env" 2>/dev/null; done
cp frontend/.env.local.example frontend/.env.local
docker compose up --build
```
