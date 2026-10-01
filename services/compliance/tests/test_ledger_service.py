import copy

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app import db, ledger_seal, ledger_service, main


class FakeLedger:
    def __init__(self):
        self.events = [
            {"id": f"e{i}", "audit_run_id": "run-1", "control_id": "CIS-NET-1.1.2", "event_type": "APPROVED",
             "actor": "admin", "ruleset_version": "1.1.0", "payload": {"i": i}, "created_at": f"2026-09-30 10:00:0{i}+00:00"}
            for i in range(4)
        ]
        self.seals = []

    async def get_ledger_events(self):
        return copy.deepcopy(self.events)

    async def get_ledger_seals(self):
        return copy.deepcopy(self.seals)

    async def insert_ledger_seal(self, seal):
        self.seals.append(copy.deepcopy(seal))


@pytest.fixture
def ledger(monkeypatch):
    fake = FakeLedger()
    monkeypatch.setattr(db, "get_ledger_events", fake.get_ledger_events)
    monkeypatch.setattr(db, "get_ledger_seals", fake.get_ledger_seals)
    monkeypatch.setattr(db, "insert_ledger_seal", fake.insert_ledger_seal)
    pem = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    monkeypatch.setenv("LEDGER_SIGNING_KEY", pem)
    return fake


async def call(method, path):
    transport = httpx.ASGITransport(app=main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        return await client.request(method, path)


@pytest.mark.asyncio
async def test_seal_verify_then_tamper_is_caught(ledger):
    assert (await call("GET", "/ledger/status")).json()["unsealed_events"] == 4
    sealed = (await call("POST", "/ledger/seal")).json()
    assert sealed["sealed"] == 4 and sealed["seq"] == 1
    assert (await call("POST", "/ledger/seal")).json()["sealed"] == 0  # nothing new

    assert (await call("GET", "/ledger/verify")).json()["ok"] is True

    ledger.events[2]["payload"] = {"i": "rewritten by an insider"}
    report = (await call("GET", "/ledger/verify")).json()
    assert report["ok"] is False and report["problems"][0]["kind"] == "modified_event"


@pytest.mark.asyncio
async def test_deleted_event_and_second_seal_chain(ledger):
    await call("POST", "/ledger/seal")
    ledger.events.append({**ledger.events[0], "id": "e9", "payload": {"late": True}, "created_at": "2026-09-30 11:00:00+00:00"})
    second = (await call("POST", "/ledger/seal")).json()
    assert second["seq"] == 2 and second["sealed"] == 1
    assert (await call("GET", "/ledger/verify")).json()["ok"] is True
    del ledger.events[1]
    kinds = [p["kind"] for p in (await call("GET", "/ledger/verify")).json()["problems"]]
    assert kinds == ["missing_event"]


@pytest.mark.asyncio
async def test_inclusion_proof_endpoint(ledger):
    await call("POST", "/ledger/seal")
    body = (await call("GET", "/ledger/proof/e2")).json()
    assert body["event"]["id"] == "e2" and body["path"] and "BEGIN PUBLIC KEY" in body["public_key"]
    assert (await call("GET", "/ledger/proof/nope")).status_code == 404


@pytest.mark.asyncio
async def test_without_a_signing_key_sealing_is_refused_not_faked(ledger, monkeypatch):
    monkeypatch.delenv("LEDGER_SIGNING_KEY")
    monkeypatch.delenv("LEDGER_SIGNING_KEY_FILE", raising=False)
    response = await call("POST", "/ledger/seal")
    assert response.status_code == 503 and "signing key" in response.json()["detail"]
    assert (await call("GET", "/ledger/status")).json()["signing_configured"] is False
