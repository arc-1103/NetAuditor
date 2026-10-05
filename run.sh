#!/usr/bin/env bash
# Bring up the core NetAuditor stack (postgres/redis/minio/opa/ollama + all
# services + frontend) via docker compose, using the model weights already
# vendored at infra/ollama/models instead of re-pulling them.
# Set PROFILES=model,advanced to also start neo4j/batfish/chromadb/learning.
set -euo pipefail
cd "$(dirname "$0")"

export OLLAMA_MODELS="$PWD/infra/ollama/models"

if ! docker info >/dev/null 2>&1; then
  echo "Starting Docker Desktop..."
  docker desktop start --timeout 300
fi

export COMPOSE_PROFILES="${PROFILES:-model}"
# Local-only low-memory overrides (git-excluded); applied whenever present.
if [[ -f docker-compose.demo.yml ]]; then
  export COMPOSE_PATH_SEPARATOR=: COMPOSE_FILE=docker-compose.yml:docker-compose.demo.yml
  echo "Using docker-compose.demo.yml overrides"
fi
docker compose up -d --build "$@"

echo
docker compose ps -a --format 'table {{.Name}}\t{{.Status}}'
echo
echo "Gateway:  http://localhost:${GATEWAY_PORT:-8000}"
echo "Frontend: http://localhost:${FRONTEND_PORT:-3000}"
echo "Logs:     docker compose logs -f"
