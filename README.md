# NetAudit Engine — SIH 2026 (PS 26155)

AI-driven multi-vendor network security compliance auditor.
See `docs/SIH26155_NetAudit_Architecture_Blueprint.md` for full architecture.

## Repo layout — start here
- `TEAM_OWNERSHIP.md` — who owns which folder, work in parallel without collisions
- `CONTRIBUTING.md` — local dev workflow, mock flags, branch naming
- `contracts/` — cross-team API/schema shapes, agree here before you build
- `services/*/.env.example` — copy to `.env` per service you're working on
- `.env.example` (root) — infra-shared values only (Postgres, Redis, ports)

## Quick start (one lane, e.g. parsing)
```
cd services/parsing
cp .env.example .env
docker compose up parsing
```

## Quick start (full stack, integration day)
```
cp .env.example .env
for d in services/*/; do cp "$d/.env.example" "$d/.env" 2>/dev/null; done
cp frontend/.env.local.example frontend/.env.local
docker compose up --build
```

## Why per-service .env files instead of one root .env
One shared `.env` means six people editing the same file = merge conflicts
and silent cross-lane breakage. Each service declares only the vars it
needs; root `.env` holds only what's genuinely shared infra (DB host,
network name). See `CONTRIBUTING.md` for the full reasoning.
