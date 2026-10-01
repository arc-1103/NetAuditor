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

## Environment variables

Six people, six machines. Without a system you get drift that nobody notices
until `docker compose up` fails in front of a judge. Three rules:

**1. `.env.example` is the source of truth; `.env` is never committed.**
Every real `.env` is gitignored. If a var isn't in the checked-in
`.env.example`, it doesn't exist as far as the team is concerned. Add the var
in the same PR as the code that needs it — not after, not "I'll mention it in
chat."

**2. Shared infra values live only in the root `.env.example`.**
`POSTGRES_DB`, `POSTGRES_USER`, `NETWORK_NAME`, port numbers — anything more
than one service needs — is defined once at the root. Service-level files
build on those values (`POSTGRES_DSN` in `services/compliance/.env.example` is
assembled from them). Change a shared value in one file and tell the team,
never in six files independently.

**3. Run `scripts/check_env.sh` before every `docker compose up`.**
It diffs every `.env` against its `.env.example` and fails loudly on a missing
key — the automated version of "did everyone actually update their env file."

When adding a variable: put it in the right `.env.example` (service-level, or
root only if genuinely shared), give it a sane default or a `changeme_`
placeholder rather than leaving it blank, and mention it in the PR description.

Don't put service-specific vars in the root `.env` "for convenience" — that is
how you end up back at one file six people fight over. Don't hardcode a value
that should be an env var "just for now"; it never gets fixed, and it silently
diverges from `.env.example`.

Full setup instructions, including per-OS prerequisites, are in
[`SETUP.md`](SETUP.md).

## Branch naming
`<lane>/<short-description>` e.g. `parsing/grammar-constrained-decoding`,
`frontend/learning-queue-view`

## Before opening a PR
- [ ] Runs standalone with mocks on (`docker compose up <your-service>`)
- [ ] Didn't touch another lane's folder without a heads-up
- [ ] If you touched `services/schema/` or `contracts/`, you tagged all
      other lane owners in the PR description

## Running the full stack (integration day only)

```bash
./scripts/setup_demo.sh      # copies every .env.example, generates secrets, checks drift
docker compose up --build -d
```

See [`SETUP.md`](SETUP.md) for the full cross-platform walkthrough.
