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


def test_topology_defaults_to_empty():
    baseline = make_baseline()
    assert baseline.topology.interfaces == []
    assert baseline.topology.routing_neighbors == []


def test_topology_interfaces_and_routing_neighbors_round_trip():
    raw = b"hostname edge01"
    baseline = SecurityBaseline(
        device={
            "detected_vendor": "cisco",
            "config_sha256": hashlib.sha256(raw).hexdigest(),
            "parsing_confidence": 0.95,
        },
        topology={
            "interfaces": [
                {"name": "GigabitEthernet0/0", "ip_address": "10.0.0.1", "subnet_mask": "255.255.255.0"}
            ],
            "routing_neighbors": [
                {"protocol": "bgp", "neighbor_ip": "10.0.0.2", "remote_asn": 65001, "local_asn": 65000}
            ],
        },
    )

    data = baseline.model_dump(mode="json")
    assert data["topology"]["interfaces"][0]["name"] == "GigabitEthernet0/0"
    assert data["topology"]["interfaces"][0]["enabled"] is True
    assert data["topology"]["routing_neighbors"][0]["remote_asn"] == 65001


def test_interface_requires_a_name():
    with pytest.raises(ValidationError):
        SecurityBaseline(
            device={
                "detected_vendor": "cisco",
                "config_sha256": hashlib.sha256(b"x").hexdigest(),
                "parsing_confidence": 0.95,
            },
            topology={"interfaces": [{"ip_address": "10.0.0.1"}]},
        )
