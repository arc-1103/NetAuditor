"""
Unit tests for app.db against an in-memory SQLite database standing in for
Postgres — same approach as services/compliance/tests/test_db.py.
"""

import json

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app import db

RUN_ID = "11111111-1111-1111-1111-111111111111"


@pytest_asyncio.fixture
async def sqlite_session(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")

    async with engine.begin() as conn:
        await conn.execute(
            text(
                """
                CREATE TABLE audit_runs (
                    id                TEXT PRIMARY KEY,
                    file_hash         TEXT NOT NULL,
                    original_filename TEXT,
                    storage_path      TEXT NOT NULL,
                    uploaded_by       TEXT,
                    status            TEXT NOT NULL DEFAULT 'INGESTED',
                    status_detail     TEXT,
                    created_at        TEXT,
                    updated_at        TEXT
                )
                """
            )
        )
        await conn.execute(
            text(
                """
                INSERT INTO audit_runs (id, file_hash, original_filename, storage_path, status)
                VALUES (:id, :hash, 'edge-rtr.cfg', 'raw-configs/abc.cfg', 'INGESTED')
                """
            ),
            {"id": RUN_ID, "hash": "b" * 64},
        )

    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(db, "async_session", session_factory)

    yield session_factory

    await engine.dispose()


@pytest.mark.asyncio
async def test_mark_needs_review_updates_status_and_detail(sqlite_session):
    await db.mark_needs_review(
        RUN_ID,
        {"reason": "unknown_or_unsupported_vendor", "detected_vendor": "unknown", "confidence": 0.0},
    )

    async with sqlite_session() as session:
        row = (
            await session.execute(
                text("SELECT status, status_detail FROM audit_runs WHERE id = :id"), {"id": RUN_ID}
            )
        ).mappings().first()

    assert row["status"] == db.STATUS_NEEDS_REVIEW
    assert json.loads(row["status_detail"]) == {
        "reason": "unknown_or_unsupported_vendor",
        "detected_vendor": "unknown",
        "confidence": 0.0,
    }


@pytest.mark.asyncio
async def test_mark_needs_review_is_a_noop_for_an_unknown_run(sqlite_session):
    """No matching row is not an error — Parsing shouldn't crash a Celery
    task retry loop over a run that was somehow never created."""
    await db.mark_needs_review("22222222-2222-2222-2222-222222222222", {"reason": "x"})

    async with sqlite_session() as session:
        count = (
            await session.execute(text("SELECT count(*) FROM audit_runs WHERE status = :s"), {"s": db.STATUS_NEEDS_REVIEW})
        ).scalar_one()

    assert count == 0
