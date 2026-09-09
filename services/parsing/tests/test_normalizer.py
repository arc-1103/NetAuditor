import pytest

from app.normalizer import (
    InvalidCanonicalTokenError,
    normalize_encryption,
    normalize_hash,
    normalize_protocol_status,
    normalize_snmp_version,
    normalize_ssh_version,
    normalize_vendor,
)


def test_vendor_aliases():
    assert normalize_vendor("Cisco IOS-XE") == "cisco"
    assert normalize_vendor("PAN-OS") == "paloalto"
    assert normalize_vendor("FortiOS") == "fortinet"


def test_unlisted_vendor_passes_through_instead_of_raising():
    assert normalize_vendor("SonicWall") == "sonicwall"
    assert normalize_vendor("Check  Point") == "check point"


def test_algorithms():
    assert normalize_hash("sha-256") == "SHA256"
    assert normalize_encryption("aes-256") == "AES256"


def test_protocol_status():
    assert normalize_protocol_status(True) == "ENABLED"
    assert normalize_protocol_status("off") == "DISABLED"
    with pytest.raises(InvalidCanonicalTokenError):
        normalize_protocol_status("maybe")


def test_unknown_semantics_are_preserved_for_absent_values():
    assert normalize_hash(None) == "UNKNOWN"
    assert normalize_hash("") == "UNKNOWN"
    assert normalize_hash("unknown") == "UNKNOWN"
    assert normalize_encryption(None) == "UNKNOWN"
    assert normalize_encryption("") == "UNKNOWN"
    assert normalize_protocol_status(None) == "UNKNOWN"
    assert normalize_protocol_status("") == "UNKNOWN"
    assert normalize_protocol_status("unknown") == "UNKNOWN"
    assert normalize_ssh_version(None) == "none"
    assert normalize_ssh_version("") == "none"
    assert normalize_ssh_version("unknown") == "none"
    assert normalize_snmp_version(None) == "none"
    assert normalize_snmp_version("") == "none"
    assert normalize_snmp_version("unknown") == "none"


@pytest.mark.parametrize("value", ["SHA999"])
def test_invalid_hash_token_is_not_hidden_as_unknown(value):
    with pytest.raises(InvalidCanonicalTokenError):
        normalize_hash(value)


@pytest.mark.parametrize("value", ["AES999"])
def test_invalid_encryption_token_is_not_hidden_as_unknown(value):
    with pytest.raises(InvalidCanonicalTokenError):
        normalize_encryption(value)


@pytest.mark.parametrize("value", ["NOT-A-PROTOCOL-STATUS"])
def test_invalid_protocol_token_is_not_hidden_as_unknown(value):
    with pytest.raises(InvalidCanonicalTokenError):
        normalize_protocol_status(value)


@pytest.mark.parametrize("value", ["STRANGE-SSH-VERSION"])
def test_invalid_ssh_version_is_not_hidden_as_unknown(value):
    with pytest.raises(InvalidCanonicalTokenError):
        normalize_ssh_version(value)
