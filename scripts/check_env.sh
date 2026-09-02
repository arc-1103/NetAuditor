#!/usr/bin/env bash
# Fails loudly if any .env is missing keys present in its .env.example,
# or if shared infra values (root .env) don't match what a service expects.
# Run this before `docker compose up` — every teammate, every time.

set -euo pipefail
FAIL=0

check_pair () {
  local example=$1
  local actual=$2
  if [[ ! -f "$actual" ]]; then
    echo "MISSING: $actual (copy from $example)"
    FAIL=1
    return
  fi
  # keys in example but missing in actual
  while IFS='=' read -r key _; do
    [[ -z "$key" || "$key" == \#* ]] && continue
    if ! grep -q "^${key}=" "$actual"; then
      echo "DRIFT: $actual is missing key '$key' (present in $example)"
      FAIL=1
    fi
  done < "$example"
}

check_pair ".env.example" ".env"
for d in services/*/; do
  [[ -f "${d}.env.example" ]] && check_pair "${d}.env.example" "${d}.env"
done
check_pair "gateway/.env.example" "gateway/.env"
check_pair "frontend/.env.local.example" "frontend/.env.local"

if [[ $FAIL -eq 1 ]]; then
  echo ""
  echo "❌ Env check failed. Fix drift above before running docker compose up."
  exit 1
else
  echo "✅ All env files present and in sync with their .env.example."
fi
