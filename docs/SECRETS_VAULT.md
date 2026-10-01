# Secrets with HashiCorp Vault

Services can read their credentials and keys from Vault at startup instead of
from `.env` files. Nothing changes until `VAULT_ADDR` is set on a service.

## What goes in Vault

Credentials and keys: Postgres and MinIO passwords, Neo4j password, the gateway
`JWT_SECRET` (or any report-signing key), the service `DATABASE_URL`s. Hashes of
uploaded configurations are not secrets — they are integrity evidence and stay
in Postgres and the ledger.

## One-time setup

1. `docker compose --profile secrets up -d vault`
2. Initialise and unseal (keep the unseal keys and root token offline, split
   between custodians):
   `docker exec netaudit-vault-1 vault operator init` then `vault operator unseal` three times.
3. Enable the secrets engine and one read-only AppRole per service:
   ```
   vault secrets enable -path=secret kv-v2
   vault policy write netaudit-gateway - <<'EOF'
   path "secret/data/netaudit/gateway" { capabilities = ["read"] }
   EOF
   vault auth enable approle
   vault write auth/approle/role/netaudit-gateway token_policies=netaudit-gateway token_ttl=1h
   ```
4. Load the current values (prints key names, never values):
   `VAULT_ADDR=http://localhost:8200 VAULT_TOKEN=<root> python infra/vault/seed.py gateway gateway/.env`
   Repeat per service (`ingestion`, `compliance`, `remediation`, `reporting`, `parsing`).
5. Remove those lines from the `.env` files, then give each service
   `VAULT_ADDR=http://vault:8200`, `VAULT_ROLE_ID`, `VAULT_SECRET_ID`
   (and `VAULT_REQUIRED=true` so it refuses to start without Vault).

## Behaviour

- Vault values override environment variables of the same name.
- If Vault is unreachable and `VAULT_REQUIRED` is not `true`, the service logs a
  warning and keeps using its environment.
- The Learning service is not wired yet (it has no `app/__init__.py`); Postgres,
  MinIO and Neo4j themselves still take their passwords from compose variables —
  Vault protects what the services hold, not those containers' own bootstrap.

## Before production

- Vault runs with plain HTTP on the internal network and file storage. Add TLS,
  audit logging (`vault audit enable file`), and auto-unseal or a documented
  unseal ceremony. Losing the unseal keys means losing the data.
- Rotate the root token after setup; use AppRole tokens for services.
