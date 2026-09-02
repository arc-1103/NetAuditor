# frontend (dashboard)

Owner: see /TEAM_OWNERSHIP.md

## Run standalone against mock data (default — don't wait on backend)
```
cp .env.local.example .env.local
npm install && npm run dev
```
Set `NEXT_PUBLIC_USE_MOCK_API=false` only once you want to hit the real gateway.

Route/response shapes: /contracts/api_gateway_routes.md
