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
    email = os.getenv("NETAUDIT_ADMIN_EMAIL", "admin@netaudit.local")
    password = os.getenv("NETAUDIT_ADMIN_PASSWORD", "changeme")
    if os.getenv("APP_ENV", "development").lower() not in {"development", "test"} and password == "changeme":
        raise RuntimeError("Set NETAUDIT_ADMIN_PASSWORD outside local development")
    password_hash = pwd_context.hash(password)
    async with engine.begin() as conn:
        await conn.execute(
            text("""
                INSERT INTO users (email, password_hash, role)
                VALUES (:email, :hash, 'admin')
                ON CONFLICT (email) DO NOTHING
            """),
            {"email": email, "hash": password_hash},
        )
    print(f"Seeded {email}. Password source: NETAUDIT_ADMIN_PASSWORD")

if __name__ == "__main__":
    asyncio.run(main())
