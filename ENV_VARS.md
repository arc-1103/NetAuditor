# Keeping Environment Variables Constant Across the Team

## The problem
Six people, six machines. Without a system, you get: someone's Postgres
DB name doesn't match what another service expects, someone forgets to
add a new var when they add a feature, and nobody notices until
`docker compose up` fails in front of a judge.

## The system (three rules)

**1. `.env.example` files are the source of truth — `.env` files are never committed.**
Every actual `.env` is in `.gitignore`. If a var isn't in the checked-in
`.env.example`, it doesn't exist as far as the team is concerned. If you
add a var your code needs, you add it to `.env.example` in the same PR —
not after, not "I'll tell people in chat."

**2. Shared infra values live in exactly one place: root `.env.example`.**
`POSTGRES_DB`, `POSTGRES_USER`, `NETWORK_NAME`, port numbers — anything
more than one service needs — is defined once at the root. Service-level
`.env.example` files reference the same values (e.g. `POSTGRES_DSN` in
`services/compliance/.env.example` is built from the root values). If you
need to change a shared value, you change it in ONE file and tell the
team, not six files independently.

**3. Run `scripts/check_env.sh` before every `docker compose up`.**
It diffs every `services/*/.env` against its `.env.example` and flags
missing keys. This is the automated version of "did everyone actually
update their env file" instead of trusting people to remember.

## When you add a new environment variable
1. Add it to the relevant `.env.example` (service-level, or root if shared).
2. Give it a sane default or a `changeme_` placeholder — never leave it blank.
3. Mention it in your PR description.
4. Anyone who pulls your change runs `scripts/check_env.sh` — it will tell
   them exactly what to add to their local `.env`.

## What NOT to do
- Don't put service-specific vars in the root `.env` "for convenience" —
  that's how you end up back at one file six people fight over.
- Don't hardcode a value in code that should be an env var "just for now"
  — it never gets fixed later, and it silently diverges from `.env.example`.
