#!/usr/bin/env bash
set -euo pipefail

copy_if_missing() {
  local source=$1 destination=$2
  if [[ ! -f "$destination" ]]; then
    cp "$source" "$destination"
    echo "Created $destination"
  fi
}

copy_if_missing .env.example .env
for directory in services/*/; do
  [[ -f "${directory}.env.example" ]] && copy_if_missing "${directory}.env.example" "${directory}.env"
done
copy_if_missing gateway/.env.example gateway/.env
copy_if_missing frontend/.env.local.example frontend/.env.local

if command -v openssl >/dev/null; then
  jwt_secret="$(openssl rand -hex 32)"
  python3 - "$jwt_secret" <<'PY'
from pathlib import Path
import sys

path = Path("gateway/.env")
lines = path.read_text().splitlines()
lines = [f"JWT_SECRET={sys.argv[1]}" if line.startswith("JWT_SECRET=") else line for line in lines]
path.write_text("\n".join(lines) + "\n")
PY
  echo "Generated a unique JWT secret in gateway/.env"
fi

./scripts/check_env.sh
echo "Environment ready. Start with: docker compose up --build -d"
