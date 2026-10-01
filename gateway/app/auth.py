"""
JWT auth: issuance (login) + validation (dependency for protected routes).
Credentials come from Postgres `users` table (see infra/postgres/init.sql).
"""
import os
import time
import httpx
import jwt
from fastapi import Header, HTTPException, Depends
from passlib.context import CryptContext
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from app.db import get_session

JWT_SECRET = os.getenv("JWT_SECRET", "changeme_generate_a_real_secret")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRY_MIN = int(os.getenv("JWT_EXPIRY_MIN", "60"))
INSECURE_DEFAULT_SECRET = "changeme_generate_a_real_secret"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# "local": users table + HS256 JWTs issued here. "keycloak": identities and
# roles come from Keycloak; this gateway only verifies its RS256 tokens.
AUTH_PROVIDER = os.getenv("AUTH_PROVIDER", "local").lower()
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://keycloak:8080").rstrip("/")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "netaudit")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "netaudit-web")
KEYCLOAK_ISSUER = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}"
ROLE_PRIORITY = ("admin", "operator", "auditor")  # highest first

_jwks_client: jwt.PyJWKClient | None = None


def _jwks() -> jwt.PyJWKClient:
    global _jwks_client
    if _jwks_client is None:
        _jwks_client = jwt.PyJWKClient(f"{KEYCLOAK_ISSUER}/protocol/openid-connect/certs", cache_keys=True)
    return _jwks_client


def _user_from_keycloak_claims(claims: dict) -> dict:
    roles = (claims.get("realm_access") or {}).get("roles") or []
    role = next((r for r in ROLE_PRIORITY if r in roles), None)
    return {
        "sub": claims["sub"], "id": claims["sub"],
        "email": claims.get("email") or claims.get("preferred_username", ""),
        "role": role,
    }


def verify_keycloak_token(token: str) -> dict:
    """Checks signature (Keycloak's published RS256 key), issuer, expiry and
    that the token was issued to our client — then maps realm roles to the
    gateway's single `role`. A user with no NetAudit role gets role=None and
    fails every roles_dependency check."""
    try:
        key = _jwks().get_signing_key_from_jwt(token)
        claims = jwt.decode(token, key.key, algorithms=["RS256"], issuer=KEYCLOAK_ISSUER, options={"verify_aud": False})
    except (jwt.PyJWTError, httpx.HTTPError):
        raise HTTPException(status_code=401, detail="Invalid token")
    if claims.get("azp") != KEYCLOAK_CLIENT_ID:
        raise HTTPException(status_code=401, detail="Invalid token")
    return _user_from_keycloak_claims(claims)


async def keycloak_login(email: str, password: str) -> tuple[str, dict]:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"{KEYCLOAK_ISSUER}/protocol/openid-connect/token",
                data={"grant_type": "password", "client_id": KEYCLOAK_CLIENT_ID, "username": email, "password": password},
            )
    except httpx.HTTPError:
        raise HTTPException(status_code=502, detail="Identity provider unavailable")
    if resp.status_code in (400, 401):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if resp.status_code >= 400:
        raise HTTPException(status_code=502, detail="Identity provider error")
    token = resp.json()["access_token"]
    user = verify_keycloak_token(token)
    if user["role"] is None:
        raise HTTPException(status_code=403, detail="This account has no NetAudit role")
    return token, user


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
    if AUTH_PROVIDER == "keycloak":
        return verify_keycloak_token(token)
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    return payload


def roles_dependency(*roles: str):
    async def dependency(user: dict = Depends(get_current_user)) -> dict:
        if user.get("role") not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return dependency


require_admin = roles_dependency("admin")
require_operator = roles_dependency("admin", "operator")
require_reader = roles_dependency("admin", "operator", "auditor")


def validate_runtime_secret() -> None:
    """Refuse a known JWT secret outside explicitly local development."""
    if os.getenv("APP_ENV", "development").lower() not in {"development", "test"}:
        if JWT_SECRET == INSECURE_DEFAULT_SECRET or len(JWT_SECRET) < 32:
            raise RuntimeError("JWT_SECRET must be a unique value of at least 32 characters")
