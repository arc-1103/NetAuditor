#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 demo/verify_fixtures.py
for schema in contracts/*.schema.json; do
  python3 -m json.tool "$schema" >/dev/null
done

lanes=(gateway services/ingestion services/parsing services/compliance
  services/learning/backend services/remediation services/reporting
  services/schema scripts)
for lane in "${lanes[@]}"; do
  echo "Testing $lane"
  (cd "$lane" && python3 -m pytest -q)
done

(cd frontend && npm run typecheck && npm run build)
if command -v docker >/dev/null 2>&1; then
  docker compose config --quiet
else
  echo "SKIP: docker compose config (Docker is not installed)"
fi
echo "All available verification gates passed."
