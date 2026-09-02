# reporting service

Owner: see /TEAM_OWNERSHIP.md

## Run standalone
```
cp .env.example .env
docker compose up reporting
```

## What this service depends on (via contract, not code)
See /contracts/ for the JSON shapes this service sends or receives.

## Mocking so you don't block on other lanes
Check .env.example for a USE_MOCK_* flag before assuming you need the full stack.
