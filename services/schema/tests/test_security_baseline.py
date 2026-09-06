import hashlib

import pytest
from pydantic import ValidationError

from schema.security_baseline import SecurityBaseline, SCHEMA_VERSION


def make_baseline(**device_overrides):
    raw = b"hostname edge01"
    device = {
        "detected_vendor": "cisco",
        "config_sha256": hashlib.sha256(raw).hexdigest(),
        "parsing_confidence": 0.95,
        **device_overrides,
    }
    return SecurityBaseline(device=device)


def test_minimal_valid_baseline():
    baseline = make_baseline()
    assert baseline.schema_version == SCHEMA_VERSION
    assert baseline.device.detected_vendor == "cisco"


def test_invalid_hash_rejected():
    with pytest.raises(ValidationError):
        make_baseline(config_sha256="bad")


def test_invalid_confidence_rejected():
    with pytest.raises(ValidationError):
        make_baseline(parsing_confidence=1.2)


def test_invalid_acl_action_rejected():
    with pytest.raises(ValidationError):
        make_baseline(
            acl={
                "ingress_entries": [{
                    "action": "allow",
                    "protocol": "ip",
                    "source": "any",
                    "destination": "any",
                }]
            }
        )


def test_serialization_uses_contract_enum_values():
    baseline = make_baseline()
    data = baseline.model_dump(mode="json")
    assert data["schema_version"] == "1.0.0"
    assert data["telnet"]["enabled"] == "UNKNOWN"
    assert data["services"]["http_server_enabled"] == "UNKNOWN"
