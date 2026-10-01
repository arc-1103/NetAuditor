"""
Gateway service — FastAPI app package.

Owns: JWT auth (issue + validate) against the Postgres `users` table, and
proxies every other route to its owning service (Ingestion, Compliance,
Learning, Remediation, Reporting). See ../Architecture.md and the
repository-root Architecture.md for the full request flow and current implementation
gaps. Route table: /contracts/api_gateway_routes.md.
"""

__version__ = "0.1.0"

# Secrets from Vault (inert unless VAULT_ADDR is set) — must run before any settings are read.
from app import vault_loader as _vault_loader

_vault_loader.load("gateway")
