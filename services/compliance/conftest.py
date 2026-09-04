"""
Presence of this file anchors pytest's import root at services/compliance/,
so `tests/*.py` can `from app import ...` without installing the package.

The Rego policies are tested separately by `opa test policies/ -v` — these
Python tests never call a live OPA server.
"""

import pytest

# Blueprint §4.2's example device, hardened, as the OPA `input` document.
# Shared by the tests that need a baseline but aren't testing policy content.
COMPLIANT_BASELINE = {
    "schema_version": "1.0.0",
    "device": {
        "raw_hostname": "CORE-SW-01",
        "detected_vendor": "cisco",
        "detected_os": "IOS-XE",
        "config_sha256": "a" * 64,
        "parsing_confidence": 0.94,
        "unknown_blocks_count": 0,
    },
    "ssh": {"enabled": True, "version": "2", "management_acl": "MGMT-SSH-ACL"},
    "telnet": {"enabled": "DISABLED"},
}


@pytest.fixture
def baseline():
    return dict(COMPLIANT_BASELINE)
