"""
Unit tests for app.db.create_audit_run. Runs against an in-memory SQLite
database standing in for Postgres, so no live database is required — the
INSERT statement itself is plain SQL, not Postgres-specific.
"""
import json

import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app import db


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
                    created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    credential_evidence TEXT
                )
                """
            )
        )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(db, "async_session", session_factory)

    yield session_factory

    await engine.dispose()


async def test_create_audit_run_inserts_expected_row(sqlite_session):
    stored = {
        "file_hash": "e" * 64,
        "storage_path": "raw-configs/eee.cfg",
        "original_filename": "device.cfg",
    }

    await db.create_audit_run("run-1", stored, "user-1")

    async with sqlite_session() as session:
        result = await session.execute(text("SELECT * FROM audit_runs WHERE id = :id"), {"id": "run-1"})
        row = result.mappings().first()

    assert row["file_hash"] == stored["file_hash"]
    assert row["storage_path"] == stored["storage_path"]
    assert row["original_filename"] == "device.cfg"
    assert row["uploaded_by"] == "user-1"
    assert row["status"] == "INGESTED"


async def test_create_audit_run_allows_missing_uploader(sqlite_session):
    stored = {"file_hash": "f" * 64, "storage_path": "raw-configs/fff.cfg", "original_filename": None}

    await db.create_audit_run("run-2", stored, None)

    async with sqlite_session() as session:
        result = await session.execute(text("SELECT uploaded_by FROM audit_runs WHERE id = :id"), {"id": "run-2"})
        row = result.mappings().first()

    assert row["uploaded_by"] is None


async def test_get_audit_run_id_by_hash_returns_the_run_after_insert(sqlite_session):
    stored = {"file_hash": "g" * 64, "storage_path": "raw-configs/ggg.cfg", "original_filename": "device.cfg"}
    await db.create_audit_run("run-3", stored, None)

    assert await db.get_audit_run_id_by_hash("g" * 64) == "run-3"


async def test_get_audit_run_id_by_hash_returns_none_when_absent(sqlite_session):
    assert await db.get_audit_run_id_by_hash("h" * 64) is None


async def test_create_audit_run_persists_credential_evidence(sqlite_session):
    evidence = [{"pattern_type": "enable_secret", "line_number": 2, "masked_value": "****", "sha256": "a" * 64}]
    stored = {
        "file_hash": "i" * 64,
        "storage_path": "raw-configs/iii.cfg",
        "original_filename": "device.cfg",
        "credential_evidence": evidence,
    }

    await db.create_audit_run("run-4", stored, None)

    async with sqlite_session() as session:
        result = await session.execute(
            text("SELECT credential_evidence FROM audit_runs WHERE id = :id"), {"id": "run-4"}
        )
        row = result.mappings().first()

    assert json.loads(row["credential_evidence"]) == evidence


async def test_create_audit_run_defaults_credential_evidence_to_empty_list(sqlite_session):
    stored = {"file_hash": "j" * 64, "storage_path": "raw-configs/jjj.cfg", "original_filename": "device.cfg"}

    await db.create_audit_run("run-5", stored, None)

    async with sqlite_session() as session:
        result = await session.execute(
            text("SELECT credential_evidence FROM audit_runs WHERE id = :id"), {"id": "run-5"}
        )
        row = result.mappings().first()

    assert json.loads(row["credential_evidence"]) == []
