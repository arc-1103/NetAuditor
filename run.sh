#!/usr/bin/env bash
# Bring up the core NetAuditor stack (postgres/redis/minio/opa/ollama + all
# services + frontend) via docker compose, using the model weights already
# vendored at infra/ollama/models instead of re-pulling them.
# Set PROFILES=model,advanced to also start neo4j/batfish/chromadb/learning.
set -euo pipefail
cd "$(dirname "$0")"

# --- Ollama model discovery --------------------------------------------------
# Reuse any Qwen already on this machine (any size, quantisation or tag, in any
# folder Ollama normally uses). Only if none exists does ollama-bootstrap pull one.
want="${OLLAMA_MODEL:-$(sed -n 's/^OLLAMA_MODEL=//p' .env 2>/dev/null | tail -1)}"
want="${want:-qwen2.5:7b}"
posix() { if command -v cygpath >/dev/null; then cygpath -u "$1"; else echo "$1"; fi; }
best_score=9 found_dir="" found_model=""
for dir in "${OLLAMA_MODELS_DIR:-}" "${OLLAMA_MODELS:-}" "$HOME/.ollama/models" \
           "$(posix "${USERPROFILE:-/nonexistent}")/.ollama/models" \
           /usr/share/ollama/.ollama/models /var/lib/ollama/models infra/ollama/models; do
  [[ -d "$dir/manifests" ]] || continue
  while IFS= read -r f; do
    rel=${f#"$dir/manifests/"}; rel=${rel#registry.ollama.ai/}; rel=${rel#library/}
    name="${rel%/*}:${rel##*/}"; lc=$(printf %s "$name" | tr '[:upper:]' '[:lower:]')
    if [[ $name == "$want" ]]; then score=0
    elif [[ $lc != *qwen* ]]; then continue
    elif [[ $lc == *vl* || $lc == *embed* || $lc == *rerank* ]]; then score=2   # last resort
    else score=1; fi
    if (( score < best_score )); then best_score=$score found_model=$name found_dir=$dir; fi
  done < <(find "$dir/manifests" -type f 2>/dev/null | sort)
done
if [[ -n $found_model ]]; then
  found_dir=$(cd "$found_dir" && pwd)
  if command -v cygpath >/dev/null; then found_dir=$(cygpath -m "$found_dir"); fi
  export OLLAMA_MODEL="$found_model" OLLAMA_MODELS_DIR="$found_dir"
  echo "Using local model $found_model from $found_dir"
else
  export OLLAMA_MODEL="$want"
  echo "No Qwen model found on this machine - will pull $want (one-time download)"
fi

# First run (or secret missing): create env files so compose can interpolate.
grep -q '^SERVICE_JWT_SECRET=.\+' .env 2>/dev/null || ./scripts/setup_demo.sh

if ! docker info >/dev/null 2>&1; then
  # `docker desktop` only exists on Docker Desktop (macOS/Windows); on Linux
  # Engine the daemon has to be started by the user.
  if docker desktop --help >/dev/null 2>&1; then
    echo "Starting Docker Desktop..."
    docker desktop start --timeout 300
  else
    echo "Docker daemon is not running - start it (e.g. 'sudo systemctl start docker')." >&2
    exit 1
  fi
fi

export COMPOSE_PROFILES="${PROFILES:-model}"
files=(-f docker-compose.yml)
# NVIDIA GPU override: only when Docker actually has the nvidia runtime.
if docker info --format '{{json .Runtimes}}' 2>/dev/null | grep -q nvidia; then
  files+=(-f docker-compose.gpu.yml)
  echo "NVIDIA runtime detected: Ollama will use the GPU"
fi
# Local-only low-memory overrides (git-excluded); applied whenever present.
if [[ -f docker-compose.demo.yml ]]; then
  files+=(-f docker-compose.demo.yml)
  echo "Using docker-compose.demo.yml overrides"
fi
docker compose "${files[@]}" up -d --build "$@"

# pgdata outlives code changes and init.sql only runs on a fresh volume, so
# apply the (idempotent) migrations on every start to avoid "relation does not exist".
docker compose "${files[@]}" up -d --wait postgres >/dev/null
bash scripts/apply_migrations.sh >/dev/null && echo "Database migrations applied."

echo
docker compose "${files[@]}" ps -a --format 'table {{.Name}}\t{{.Status}}'
echo
echo "Gateway:  http://localhost:${GATEWAY_PORT:-8000}"
echo "Frontend: http://localhost:${FRONTEND_PORT:-3000}"
echo "Logs:     docker compose logs -f"
