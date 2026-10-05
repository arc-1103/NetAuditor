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
  # .bak suffix keeps sed -i working on both GNU and BSD/macOS sed.
  sed -i.bak "s/^JWT_SECRET=.*/JWT_SECRET=$(openssl rand -hex 32)/" gateway/.env && rm -f gateway/.env.bak
  echo "Generated a unique JWT secret in gateway/.env"
fi

# Shared key for signed service-to-service tokens (Learning service authentication).
if ! grep -q '^SERVICE_JWT_SECRET=.\+' .env; then
  if command -v openssl >/dev/null; then
    sed -i.bak '/^SERVICE_JWT_SECRET=/d' .env && rm -f .env.bak # .bak suffix: BSD/macOS sed needs one
    echo "SERVICE_JWT_SECRET=$(openssl rand -hex 32)" >> .env
    echo "Generated SERVICE_JWT_SECRET in .env"
  else
    echo "WARNING: openssl not found - set SERVICE_JWT_SECRET in .env yourself (compose will not start without it)"
  fi
fi

./scripts/check_env.sh
echo "Environment ready. Start with: docker compose up --build -d"
