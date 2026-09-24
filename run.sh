#!/usr/bin/env bash
# Bring up the core NetAuditor stack (postgres/redis/minio/opa/ollama + all
# services + frontend) via docker compose, using the model weights already
# vendored at infra/ollama/models instead of re-pulling them.
# Set PROFILES=model,advanced to also start neo4j/batfish/chromadb/learning.
set -euo pipefail
cd "$(dirname "$0")"

export OLLAMA_MODELS="$PWD/infra/ollama/models"

if ! docker info >/dev/null 2>&1; then
  echo "Docker daemon not running. Start Docker Desktop, then re-run this script." >&2
  if [[ "$OSTYPE" == darwin* ]]; then
    open -a Docker
    echo "Waiting for Docker to start..."
    until docker info >/dev/null 2>&1; do sleep 2; done
  else
    exit 1
  fi
fi

export COMPOSE_PROFILES="${PROFILES:-model}"
docker compose up -d --build "$@"

echo
echo "Gateway:  http://localhost:${GATEWAY_PORT:-8000}"
echo "Frontend: http://localhost:${FRONTEND_PORT:-3000}"
echo "Logs:     docker compose logs -f"
