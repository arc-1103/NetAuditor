"""Signed service-to-service tokens (HS256 JWT, stdlib only).

Replaces trusting a plaintext header such as `X-User-Role`. The caller signs a
short-lived token with the shared SERVICE_JWT_SECRET; the Learning service
verifies the signature, issuer, audience and expiry, and takes the caller's
role from the *signed* claims. Anyone who can reach the port but does not hold
the secret cannot assert a role.

Roles in use: the gateway signs the real user's role (admin, operator,
auditor); Parsing, Compliance and Remediation sign as `service_worker`, an
explicit internal principal that Learning treats as an elevated reader (see
app/access.py). Queued background tasks carry a longer-lived token (`ttl`).

Limits: HS256 means every holder of the secret (gateway, parsing, compliance,
remediation, learning) can mint tokens as any caller, so the claims prove
"a NetAudit service vouches for this", not which one. A token can be replayed
until it expires (60 s by default). Asymmetric keys would fix the first point
at the cost of key distribution; Keycloak already covers end-user identity at
the gateway.

Identical copies live in gateway/, parsing/, compliance/ and remediation/
(a test enforces it).
"""
import base64
import hashlib
import hmac
import json
import os
import time
import uuid

AUDIENCE = "learning"
TTL_SECONDS = int(os.getenv("SERVICE_JWT_TTL_SECONDS", "60"))
_HEADER = {"alg": "HS256", "typ": "JWT"}


class TokenError(ValueError):  # ValueError so callers that already fail open on bad input do so here too
    pass


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _sign(signing_input: str, secret: str) -> str:
    return _b64(hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest())


def mint(issuer: str, subject: str, role: str, secret: str | None = None, now: float | None = None, ttl: int | None = None) -> str:
    secret = secret or os.getenv("SERVICE_JWT_SECRET", "")
    if not secret:
        raise TokenError("SERVICE_JWT_SECRET is not set")
    now = int(time.time() if now is None else now)
    claims = {"iss": issuer, "sub": subject, "role": role, "aud": AUDIENCE, "iat": now,
              "exp": now + (TTL_SECONDS if ttl is None else ttl), "jti": uuid.uuid4().hex}
    signing_input = _b64(json.dumps(_HEADER, separators=(",", ":")).encode()) + "." + _b64(json.dumps(claims, separators=(",", ":")).encode())
    return signing_input + "." + _sign(signing_input, secret)


def verify(token: str, secret: str | None = None, now: float | None = None) -> dict:
    secret = secret or os.getenv("SERVICE_JWT_SECRET", "")
    if not secret:
        raise TokenError("SERVICE_JWT_SECRET is not set")
    try:
        head_b64, body_b64, sig = token.split(".")
        header = json.loads(_unb64(head_b64))
        claims = json.loads(_unb64(body_b64))
    except (ValueError, AttributeError, UnicodeDecodeError) as exc:
        raise TokenError("malformed token") from exc
    if header.get("alg") != "HS256":  # never honour the token's own choice (alg=none attack)
        raise TokenError("unsupported algorithm")
    if not hmac.compare_digest(sig, _sign(f"{head_b64}.{body_b64}", secret)):
        raise TokenError("bad signature")
    now = time.time() if now is None else now
    if claims.get("aud") != AUDIENCE:
        raise TokenError("wrong audience")
    if not isinstance(claims.get("exp"), (int, float)) or claims["exp"] <= now:
        raise TokenError("token expired")
    if not claims.get("sub") or not claims.get("iss"):
        raise TokenError("missing subject or issuer")
    return claims


def auth_headers(issuer: str, subject: str, role: str) -> dict:
    return {"Authorization": f"Bearer {mint(issuer, subject, role)}"}
