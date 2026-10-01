"""
Ingestion service — FastAPI app package.

Owns: file upload validation, SHA-256 dedup, MinIO storage, AuditRun
persistence, and dispatching parsing jobs to Celery/Redis. See
the repository-root Architecture.md for the full request flow.
"""

__version__ = "0.1.0"

# Secrets from Vault (inert unless VAULT_ADDR is set) — must run before any settings are read.
from app import vault_loader as _vault_loader

_vault_loader.load("ingestion")
