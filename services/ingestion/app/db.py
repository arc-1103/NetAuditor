"""
Postgres access for AuditRun records. Ingestion owns the `audit_runs`
table (see infra/postgres/init.sql) — mirrors gateway/app/db.py's
connection pattern for the shared Postgres instance.
"""
import os
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

POSTGRES_DSN = os.getenv(
    "POSTGRES_DSN",
    "postgresql+asyncpg://netaudit:changeme_in_local_env@postgres:5432/netaudit",
)

engine = create_async_engine(POSTGRES_DSN, echo=False)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_audit_run_id_by_hash(file_hash: str) -> str | None:
    async with async_session() as session:
        result = await session.execute(
            text("SELECT id FROM audit_runs WHERE file_hash = :file_hash ORDER BY created_at DESC LIMIT 1"),
            {"file_hash": file_hash},
        )
        return result.scalar_one_or_none()


async def create_audit_run(run_id: str, stored: dict, uploaded_by: str | None) -> None:
    async with async_session() as session:
        await session.execute(
            text(
                """
                INSERT INTO audit_runs
                    (id, file_hash, original_filename, storage_path, uploaded_by, status)
                VALUES
                    (:id, :file_hash, :original_filename, :storage_path, :uploaded_by, 'INGESTED')
                """
            ),
            {
                "id": run_id,
                "file_hash": stored["file_hash"],
                "original_filename": stored.get("original_filename"),
                "storage_path": stored["storage_path"],
                "uploaded_by": uploaded_by,
            },
        )
        await session.commit()
