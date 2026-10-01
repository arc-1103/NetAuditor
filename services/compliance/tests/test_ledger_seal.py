import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app import ledger_seal as ls
from app import merkle

KEY = Ed25519PrivateKey.generate()


def event(i, **overrides):
    base = {"id": f"e{i:03d}", "audit_run_id": "run-1", "control_id": "CIS-NET-1.1.2", "event_type": "APPROVED",
            "actor": "admin@x", "ruleset_version": "1.1.0", "payload": {"n": i}, "created_at": f"2026-09-30T10:00:{i:02d}+00:00"}
    return {**base, **overrides}


def build(first=0, count=3, previous=None):
    events = [event(i) for i in range(first, first + count)]
    return events, ls.build_seal(events, previous, KEY)


def check(seals, events):
    by_id = {e["id"]: e for e in events}
    return ls.verify_chain(seals, by_id, KEY.public_key(), set(by_id))


def two_seals():
    e1, s1 = build(0, 3)
    e2, s2 = build(3, 2, previous=s1)
    return [s1, s2], e1 + e2


def test_untouched_chain_verifies_and_reports_its_head():
    seals, events = two_seals()
    report = check(seals, events)
    assert report["ok"] and report["seals"] == 2 and report["events_sealed"] == 5 and report["unsealed_events"] == 0
    assert report["head"] == {"seq": 2, "hash": ls.seal_hash(seals[1])}


def test_modifying_a_sealed_event_is_detected():
    seals, events = two_seals()
    events[1] = {**events[1], "payload": {"n": 999}}
    assert [p["kind"] for p in check(seals, events)["problems"]] == ["modified_event"]


def test_deleting_a_sealed_event_is_detected():
    seals, events = two_seals()
    report = check(seals, events[:1] + events[2:])
    assert report["problems"][0]["kind"] == "missing_event" and not report["ok"]


def test_rewriting_a_seal_without_the_key_fails_its_signature():
    seals, events = two_seals()
    forged = copy.deepcopy(seals)
    forged[0]["merkle_root"] = "00" * 32
    kinds = {p["kind"] for p in check(forged, events)["problems"]}
    assert "bad_signature" in kinds


def test_removing_a_middle_seal_breaks_the_chain():
    e1, s1 = build(0, 2)
    e2, s2 = build(2, 2, previous=s1)
    e3, s3 = build(4, 2, previous=s2)
    kinds = {p["kind"] for p in check([s1, s3], e1 + e2 + e3)["problems"]}
    assert "chain_break" in kinds or "sequence_gap" in kinds


def test_new_events_are_reported_unsealed_not_as_tampering():
    seals, events = two_seals()
    report = check(seals, events + [event(9)])
    assert report["ok"] and report["unsealed_events"] == 1


def test_inclusion_proof_ties_one_event_to_the_signed_root():
    seals, events = two_seals()
    by_id = {e["id"]: e for e in events}
    proof = ls.inclusion_proof(seals[0], by_id, "e001")
    leaf = merkle.leaf_hash(ls.canonical_event(by_id["e001"]))
    assert merkle.verify_proof(leaf, proof["path"], bytes.fromhex(proof["seal"]["merkle_root"]))
    KEY.public_key().verify(bytes.fromhex(proof["seal"]["signature"]), ls.header_bytes(proof["seal"]))
    with pytest.raises(ls.LedgerSealError):
        ls.inclusion_proof(seals[0], by_id, "e004")


def test_cannot_seal_nothing_and_key_loading(monkeypatch, tmp_path):
    with pytest.raises(ls.LedgerSealError):
        ls.build_seal([], None, KEY)
    monkeypatch.delenv("LEDGER_SIGNING_KEY", raising=False)
    monkeypatch.delenv("LEDGER_SIGNING_KEY_FILE", raising=False)
    assert ls.load_signing_key() is None
    from cryptography.hazmat.primitives import serialization
    pem = KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    (tmp_path / "k.pem").write_bytes(pem)
    monkeypatch.setenv("LEDGER_SIGNING_KEY_FILE", str(tmp_path / "k.pem"))
    assert ls.key_id(ls.load_signing_key()) == ls.key_id(KEY)
