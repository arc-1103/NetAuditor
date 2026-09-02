"""
Creates a demo admin user in Postgres for local login testing.
Run once after `docker compose up postgres`:
    python scripts/seed_admin.py
"""
import asyncio
import os
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
DSN = os.getenv("POSTGRES_DSN", "postgresql+asyncpg://netaudit:changeme_in_local_env@localhost:5432/netaudit")


async def main():
    engine = create_async_engine(DSN)
    password_hash = pwd_context.hash("changeme")
    async with engine.begin() as conn:
        await conn.execute(
            text("""
                INSERT INTO users (email, password_hash, role)
                VALUES (:email, :hash, 'admin')
                ON CONFLICT (email) DO NOTHING
            """),
            {"email": "admin@netaudit.local", "hash": password_hash},
        )
    print("Seeded admin@netaudit.local / changeme")

if __name__ == "__main__":
    asyncio.run(main())
