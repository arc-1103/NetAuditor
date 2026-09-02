"""
Ingestion service — FastAPI app package.

Owns: file upload validation, SHA-256 dedup, MinIO storage, AuditRun
persistence, and dispatching parsing jobs to Celery/Redis. See
../Architecture.md and ../BluePrint.md for the full request flow.
"""

__version__ = "0.1.0"
