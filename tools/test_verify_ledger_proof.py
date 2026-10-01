import copy
import importlib.util
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import verify_ledger_proof as v

# Load the service's own sealing code to prove the independent verifier agrees with it.
COMPLIANCE = Path(__file__).resolve().parents[1] / "services" / "compliance"


@pytest.fixture(scope="module")
def service():
    sys.path.insert(0, str(COMPLIANCE))
    try:
        import app.ledger_seal as ledger_seal
        yield ledger_seal
    finally:
        sys.path.remove(str(COMPLIANCE))
        for name in [n for n in sys.modules if n == "app" or n.startswith("app.")]:
            del sys.modules[name]


def make_proof(service):
    key = Ed25519PrivateKey.generate()
    events = [{"id": f"e{i}", "audit_run_id": "r", "control_id": "C", "event_type": "APPROVED", "actor": "a",
               "ruleset_version": "1", "payload": {"i": i}, "created_at": f"2026-09-30 10:00:0{i}+00:00"} for i in range(5)]
    seal = service.build_seal(events, None, key)
    proof = service.inclusion_proof(seal, {e["id"]: e for e in events}, "e3")
    return {**proof, "event": events[3], "public_key": service.public_key_pem(key)}, key


def test_verifier_agrees_with_the_service_and_rejects_tampering(service):
    proof, key = make_proof(service)
    assert v.verify(proof) == []
    tampered = copy.deepcopy(proof)
    tampered["event"]["payload"] = {"i": "changed"}
    assert any("leaf hash" in f for f in v.verify(tampered))
    wrong_key = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    assert any("signature" in f for f in v.verify(proof, wrong_key))
    forged = copy.deepcopy(proof)
    forged["seal"]["merkle_root"] = "00" * 32
    assert v.verify(forged)
