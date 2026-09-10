#!/usr/bin/env bash
set -euo pipefail

for migration in infra/postgres/migrations/*.sql; do
  echo "Applying $migration"
  docker compose exec -T postgres psql -v ON_ERROR_STOP=1 \
    -U "${POSTGRES_USER:-netaudit}" -d "${POSTGRES_DB:-netaudit}" < "$migration"
done
echo "Database migrations applied."
