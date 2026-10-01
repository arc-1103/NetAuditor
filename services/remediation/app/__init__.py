"""NetAudit deterministic remediation service."""


# Secrets from Vault (inert unless VAULT_ADDR is set) — must run before any settings are read.
from app import vault_loader as _vault_loader

_vault_loader.load("remediation")
