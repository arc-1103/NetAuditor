"""
Postgres access for the Parsing lane's audit-run status updates.

Parsing does not own `audit_runs` (see infra/postgres/init.sql) - Ingestion
creates the row and Compliance advances it to EVALUATED - but a job that
never reaches Compliance (unsupported vendor, or confidence below threshold)
needs to update it too, or the run stalls at INGESTED forever with no trace
of why. Mirrors services/compliance/app/db.py's connection pattern for the
shared Postgres instance.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from .config import settings

STATUS_NEEDS_REVIEW = "NEEDS_REVIEW"

engine = create_async_engine(settings.postgres_dsn, echo=False)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def mark_needs_review(audit_run_id: str, detail: dict[str, Any]) -> None:
    """Record why a job could not reach Compliance, so the run doesn't stall
    at INGESTED with no visible reason. Overwrites any prior status_detail —
    a job is only ever processed once per Celery dispatch, so there is
    nothing to accumulate.
    """
    async with async_session() as session, session.begin():
        await session.execute(
            text(
                """
                UPDATE audit_runs
                SET status = :status, status_detail = :detail, updated_at = :updated_at
                WHERE id = :run_id
                """
            ),
            {
                "status": STATUS_NEEDS_REVIEW,
                "detail": json.dumps(detail),
                "updated_at": datetime.now(timezone.utc),
                "run_id": audit_run_id,
            },
        )
