import base64
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import service_token as st

SECRET = "s3cret-for-tests"


def b64(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def test_roundtrip_carries_signed_claims():
    claims = st.verify(st.mint("gateway", "u-1", "admin", secret=SECRET), secret=SECRET)
    assert (claims["sub"], claims["role"], claims["iss"], claims["aud"]) == ("u-1", "admin", "gateway", "learning")


@pytest.mark.parametrize("mutate", ["tampered_role", "wrong_secret", "expired", "alg_none", "wrong_audience", "garbage"])
def test_forged_or_stale_tokens_are_rejected(mutate):
    good = st.mint("gateway", "u-1", "auditor", secret=SECRET, now=1_000_000)
    head, body, sig = good.split(".")
    claims = json.loads(base64.urlsafe_b64decode(body + "=="))
    now = 1_000_010
    if mutate == "tampered_role":
        token = f"{head}.{b64({**claims, 'role': 'admin'})}.{sig}"
    elif mutate == "wrong_secret":
        token = st.mint("gateway", "u-1", "admin", secret="other", now=1_000_000)
    elif mutate == "expired":
        token, now = good, 1_000_000 + st.TTL_SECONDS + 1
    elif mutate == "alg_none":
        token = f"{b64({'alg': 'none', 'typ': 'JWT'})}.{body}."
    elif mutate == "wrong_audience":
        token = f"{head}.{b64({**claims, 'aud': 'other'})}.{sig}"  # also breaks the signature; covered separately below
        with pytest.raises(st.TokenError):
            st.verify(token, secret=SECRET, now=now)
        forged = {**claims, "aud": "other"}
        signing = f"{head}.{b64(forged)}"
        token = f"{signing}.{st._sign(signing, SECRET)}"  # validly signed, wrong audience
    else:
        token = "not-a-jwt"
    with pytest.raises(st.TokenError):
        st.verify(token, secret=SECRET, now=now)


def test_all_service_copies_are_identical():
    services = Path(__file__).resolve().parents[3]
    src = Path(st.__file__).read_bytes()
    for copy in [services / "parsing/app", services / "compliance/app", services / "remediation/app", services.parent / "gateway/app"]:
        assert (copy / "service_token.py").read_bytes() == src, copy


def client(monkeypatch, secret=SECRET):
    from app.main import app
    if secret:
        monkeypatch.setenv("SERVICE_JWT_SECRET", secret)
    else:
        monkeypatch.delenv("SERVICE_JWT_SECRET", raising=False)
    return TestClient(app)


def test_only_health_is_open_and_plaintext_role_headers_are_ignored(monkeypatch):
    c = client(monkeypatch)
    assert c.get("/health").status_code == 200
    assert c.get("/learning/queue").status_code == 401
    spoof = {"X-User-Role": "admin", "X-User-Id": "attacker"}
    assert c.post("/learning/search", json={"query": "q"}, headers=spoof).status_code == 401
    assert c.post("/learning/map", json={}, headers=spoof).status_code == 401
    assert c.get("/learning/queue", headers={"Authorization": "Bearer forged.token.here"}).status_code == 401


def test_a_valid_token_reaches_the_route_and_fails_closed_without_a_secret(monkeypatch):
    c = client(monkeypatch)
    token = st.mint("gateway", "u-1", "auditor", secret=SECRET)
    # non-admin may not confirm a mapping, proven by the signed role, not a header
    r = c.post("/learning/map", json={"block_id": "b", "cli_pattern": "x", "field": "f", "value": "v"},
               headers={"Authorization": f"Bearer {token}", "X-User-Role": "admin"})
    assert r.status_code == 403
    assert client(monkeypatch, secret=None).get("/learning/queue", headers={"Authorization": f"Bearer {token}"}).status_code == 503
