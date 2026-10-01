import time
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

from app import auth

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(autouse=True)
def fake_jwks(monkeypatch):
    jwks = SimpleNamespace(get_signing_key_from_jwt=lambda token: SimpleNamespace(key=KEY.public_key()))
    monkeypatch.setattr(auth, "_jwks", lambda: jwks)


def token(roles=("admin",), key=KEY, **overrides):
    claims = {
        "sub": "user-1", "email": "a@netaudit.local", "iss": auth.KEYCLOAK_ISSUER,
        "azp": auth.KEYCLOAK_CLIENT_ID, "exp": int(time.time()) + 300,
        "realm_access": {"roles": list(roles)},
    }
    claims.update(overrides)
    return jwt.encode(claims, key, algorithm="RS256")


def test_valid_token_maps_identity_and_highest_role():
    user = auth.verify_keycloak_token(token(roles=("auditor", "operator")))
    assert user == {"sub": "user-1", "id": "user-1", "email": "a@netaudit.local", "role": "operator"}


def test_token_without_a_netaudit_role_has_no_role():
    assert auth.verify_keycloak_token(token(roles=("offline_access",)))["role"] is None


@pytest.mark.parametrize("bad", [
    lambda: token(key=OTHER_KEY),
    lambda: token(iss="http://evil/realms/netaudit"),
    lambda: token(azp="some-other-client"),
    lambda: token(exp=int(time.time()) - 10),
])
def test_forged_wrong_issuer_wrong_client_or_expired_tokens_are_rejected(bad):
    with pytest.raises(HTTPException) as exc:
        auth.verify_keycloak_token(bad())
    assert exc.value.status_code == 401
