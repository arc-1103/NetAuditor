"""
JWT auth: issuance (login) + validation (dependency for protected routes).
Credentials come from Postgres `users` table (see infra/postgres/init.sql).
"""
import os
import time
import jwt
from fastapi import Header, HTTPException, Depends
from passlib.context import CryptContext
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from app.db import get_session

JWT_SECRET = os.getenv("JWT_SECRET", "changeme_generate_a_real_secret")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRY_MIN = int(os.getenv("JWT_EXPIRY_MIN", "60"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


async def authenticate_user(email: str, password: str, session: AsyncSession) -> dict:
    result = await session.execute(
        text("SELECT id, email, password_hash, role FROM users WHERE email = :email"),
        {"email": email},
    )
    row = result.mappings().first()
    if not row or not pwd_context.verify(password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"id": str(row["id"]), "email": row["email"], "role": row["role"]}


def issue_token(user: dict) -> str:
    payload = {
        "sub": user["id"],
        "email": user["email"],
        "role": user["role"],
        "exp": int(time.time()) + JWT_EXPIRY_MIN * 60,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


async def get_current_user(authorization: str = Header(default=None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    return payload
