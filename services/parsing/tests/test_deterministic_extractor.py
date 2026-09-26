"""
Unit tests for app.deterministic_extractor — docs/action.md Phase 1.

Validated against the repo's real demo/*.cfg fixtures (not synthetic
inline text) wherever a fixture already exists for the vendor/field being
tested, since those are the actual configs this cross-check has to agree
with the SLM about.
"""

from pathlib import Path

import pytest

from app.deterministic_extractor import EmptyDeterministicExtractorProvider, TextFSMExtractor

DEMO_DIR = Path(__file__).parents[3] / "demo"


def _demo(name: str) -> str:
    return (DEMO_DIR / name).read_text(encoding="utf-8")


extractor = TextFSMExtractor()


def test_empty_provider_always_abstains():
    assert EmptyDeterministicExtractorProvider().extract("hostname R1\n", "cisco") == {}


def test_unsupported_vendor_abstains_entirely():
    assert extractor.extract("hostname R1\n", "junos") == {}
    assert extractor.extract("hostname R1\n", "") == {}


# ── cisco: demo/cisco_hardened.cfg ────────────────────────────────────
def test_cisco_hardened_scalars():
    baseline = extractor.extract(_demo("cisco_hardened.cfg"), "cisco")

    assert baseline["device"]["raw_hostname"] == "branch-core-02"
    assert baseline["aaa"]["password_encryption"] == "ENABLED"
    assert baseline["ssh"] == {"enabled": True, "version": "2", "management_acl": "MANAGEMENT-ONLY"}
    assert baseline["telnet"]["enabled"] == "DISABLED"
    assert baseline["services"]["http_server_enabled"] == "DISABLED"
    assert baseline["services"]["https_server_enabled"] == "ENABLED"
    assert baseline["snmp"]["enabled"] is True
    assert baseline["snmp"]["version"] == "v3"
    assert "community_strings" not in baseline["snmp"]  # v3, no community strings in this fixture
    assert baseline["ntp"] == {"authentication_enabled": True, "enabled": True, "servers": ["10.20.10.20"]}
    assert baseline["logging"]["syslog_enabled"] is True
    assert baseline["logging"]["syslog_hosts"] == ["10.20.10.12"]
    assert baseline["banners"]["login_banner_present"] is True


def test_cisco_hardened_ike_policy():
    baseline = extractor.extract(_demo("cisco_hardened.cfg"), "cisco")

    assert baseline["crypto"]["ike_policies"] == [{
        "policy_id": 10, "encryption": "AES256", "hash_algorithm": "SHA256",
        "dh_group": 14, "authentication_method": "pre-share",
    }]


def test_cisco_hardened_acl_entries():
    baseline = extractor.extract(_demo("cisco_hardened.cfg"), "cisco")

    assert baseline["acl"]["ingress_acl_name"] == "MANAGEMENT-ONLY"
    assert baseline["acl"]["ingress_acl_applied"] is True
    entries = baseline["acl"]["ingress_entries"]
    assert entries[0]["action"] == "permit"
    assert entries[0]["source"] == "10.20.10.0 0.0.0.255"
    assert entries[1] == {"sequence": None, "action": "deny", "protocol": "ip", "source": "any", "destination": "any", "port": None}


def test_cisco_hardened_interface():
    baseline = extractor.extract(_demo("cisco_hardened.cfg"), "cisco")

    assert baseline["topology"]["interfaces"] == [{
        "name": "GigabitEthernet0/0", "ip_address": "10.20.0.5", "subnet_mask": "255.255.255.252",
        "description": "WAN uplink", "enabled": True,
    }]


# ── cisco: demo/cisco_insecure.cfg — the opposite extremes ────────────
def test_cisco_insecure_scalars():
    baseline = extractor.extract(_demo("cisco_insecure.cfg"), "cisco")

    assert baseline["aaa"]["password_encryption"] == "DISABLED"
    assert baseline["ssh"]["version"] == "1"
    assert baseline["telnet"]["enabled"] == "ENABLED"
    assert baseline["services"]["http_server_enabled"] == "ENABLED"
    assert baseline["services"]["https_server_enabled"] == "DISABLED"
    assert baseline["snmp"]["community_strings"] == ["public"]
    assert baseline["snmp"]["version"] == "v2c"
    # No banner login line anywhere in this fixture — fail-closed on
    # absence, matching generic_level1.rego's own CIS-NET-1.6.1 treatment.
    assert baseline["banners"]["login_banner_present"] is False
    assert baseline["logging"]["syslog_enabled"] is False
    assert "syslog_hosts" not in baseline["logging"]


def test_cisco_insecure_weak_ike_policy():
    baseline = extractor.extract(_demo("cisco_insecure.cfg"), "cisco")

    assert baseline["crypto"]["ike_policies"] == [{
        "policy_id": 10, "encryption": "3DES", "hash_algorithm": "MD5",
        "dh_group": 2, "authentication_method": "pre-share",
    }]


# ── cisco: demo/cisco_multi_device_datacenter.cfg — multiple interfaces
#    and BGP neighbors ─────────────────────────────────────────────────
def test_cisco_datacenter_multiple_interfaces():
    baseline = extractor.extract(_demo("cisco_multi_device_datacenter.cfg"), "cisco")

    names = [i["name"] for i in baseline["topology"]["interfaces"]]
    assert names == ["GigabitEthernet0/0", "GigabitEthernet0/1", "GigabitEthernet0/2"]


def test_cisco_datacenter_bgp_neighbors():
    baseline = extractor.extract(_demo("cisco_multi_device_datacenter.cfg"), "cisco")

    assert baseline["topology"]["routing_neighbors"] == [
        {"protocol": "bgp", "neighbor_ip": "10.100.0.2", "remote_asn": 65002, "local_asn": 65001},
        {"protocol": "bgp", "neighbor_ip": "10.100.0.6", "remote_asn": 65003, "local_asn": 65001},
    ]


# ── cisco: demo/cisco_minimal_edge.cfg — sparse config, most fields absent
def test_cisco_minimal_edge_abstains_on_unconfigured_sections():
    baseline = extractor.extract(_demo("cisco_minimal_edge.cfg"), "cisco")

    assert "crypto" not in baseline  # no crypto isakmp block in this fixture
    assert "snmp" not in baseline  # no snmp lines at all
    assert baseline["ssh"]["version"] == "2"
    # No banner login and no logging host — still directly assertable False.
    assert baseline["banners"]["login_banner_present"] is False
    assert baseline["logging"]["syslog_enabled"] is False


def test_cisco_no_vty_transport_line_abstains_on_telnet():
    """A config with no `line vty`/`transport input` at all must not
    assert telnet.enabled either way — there's no evidence."""
    baseline = extractor.extract("hostname R1\nip ssh version 2\n", "cisco")

    assert "telnet" not in baseline


@pytest.mark.parametrize("fixture", [
    "cisco_all_findings.cfg", "cisco_snmp_only.cfg", "cisco_telnet_only.cfg", "cisco_weak_crypto.cfg",
])
def test_every_cisco_demo_fixture_parses_without_error(fixture):
    """Smoke test across every remaining cisco fixture — must not raise,
    and must always report a hostname (every fixture has one)."""
    baseline = extractor.extract(_demo(fixture), "cisco")

    assert baseline["device"]["raw_hostname"]


# ── fortinet: demo/fortinet_hardened.conf ─────────────────────────────
def test_fortinet_hardened_scalars():
    baseline = extractor.extract(_demo("fortinet_hardened.conf"), "fortinet")

    assert baseline["device"]["raw_hostname"] == "edge-fw-02"
    assert baseline["telnet"]["enabled"] == "DISABLED"
    assert baseline["snmp"]["enabled"] is True
    assert baseline["snmp"]["version"] == "v3"
    assert "community_strings" not in baseline["snmp"]
    assert baseline["banners"]["login_banner_present"] is True
    assert baseline["logging"]["syslog_enabled"] is True
    assert baseline["logging"]["syslog_hosts"] == ["10.30.10.30"]


def test_fortinet_hardened_ike_proposal():
    baseline = extractor.extract(_demo("fortinet_hardened.conf"), "fortinet")

    assert baseline["crypto"]["ike_policies"] == [
        {"policy_id": None, "encryption": "AES256", "hash_algorithm": "SHA256", "dh_group": None, "authentication_method": None},
    ]


# ── fortinet: demo/fortinet_insecure.conf ─────────────────────────────
def test_fortinet_insecure_scalars():
    baseline = extractor.extract(_demo("fortinet_insecure.conf"), "fortinet")

    assert baseline["telnet"]["enabled"] == "ENABLED"
    assert baseline["snmp"]["community_strings"] == ["public"]
    assert baseline["snmp"]["version"] == "v2c"
    assert baseline["banners"]["login_banner_present"] is False
    assert baseline["logging"]["syslog_enabled"] is False


def test_fortinet_insecure_weak_ike_proposal_has_two_legacy_policies():
    """"set proposal des-md5 3des-sha1" is two legacy proposals on one line."""
    baseline = extractor.extract(_demo("fortinet_insecure.conf"), "fortinet")

    assert baseline["crypto"]["ike_policies"] == [
        {"policy_id": None, "encryption": "DES", "hash_algorithm": "MD5", "dh_group": None, "authentication_method": None},
        {"policy_id": None, "encryption": "3DES", "hash_algorithm": "SHA1", "dh_group": None, "authentication_method": None},
    ]


def test_fortinet_snmp_weak_isolates_the_single_issue():
    baseline = extractor.extract(_demo("fortinet_snmp_weak.conf"), "fortinet")

    assert baseline["telnet"]["enabled"] == "DISABLED"
    assert baseline["snmp"]["community_strings"] == ["public"]
    assert baseline["logging"]["syslog_enabled"] is True


# ── juniper: demo/juniper_hardened.conf ───────────────────────────────
def test_juniper_hardened_scalars():
    baseline = extractor.extract(_demo("juniper_hardened.conf"), "juniper")

    assert baseline["device"]["raw_hostname"] == "edge-router-jnpr-02"
    assert baseline["telnet"]["enabled"] == "DISABLED"
    assert baseline["ssh"]["enabled"] is True
    assert baseline["services"]["http_server_enabled"] == "DISABLED"
    assert baseline["aaa"]["password_encryption"] == "ENABLED"
    assert baseline["snmp"]["enabled"] is True
    assert baseline["snmp"]["version"] == "v3"
    assert "community_strings" not in baseline["snmp"]
    assert baseline["ntp"] == {"enabled": True, "servers": ["10.40.10.20"], "authentication_enabled": True}
    assert baseline["banners"]["login_banner_present"] is True
    assert baseline["logging"]["syslog_hosts"] == ["10.40.10.30"]


# ── juniper: demo/juniper_insecure.conf ───────────────────────────────
def test_juniper_insecure_scalars():
    baseline = extractor.extract(_demo("juniper_insecure.conf"), "juniper")

    assert baseline["telnet"]["enabled"] == "ENABLED"
    assert baseline["services"]["http_server_enabled"] == "ENABLED"
    assert baseline["aaa"]["password_encryption"] == "DISABLED"
    assert baseline["snmp"]["community_strings"] == ["public"]  # deduped from two lines
    assert baseline["snmp"]["version"] == "v2c"
    assert baseline["banners"]["login_banner_present"] is False
    assert "authentication_enabled" not in baseline["ntp"]  # no ntp authentication-key line — abstain, not False


# ── paloalto: demo/paloalto_hardened.conf ─────────────────────────────
def test_paloalto_hardened_scalars():
    baseline = extractor.extract(_demo("paloalto_hardened.conf"), "paloalto")

    assert baseline["device"]["raw_hostname"] == "pan-fw-edge-02"
    assert baseline["telnet"]["enabled"] == "DISABLED"
    assert baseline["services"]["http_server_enabled"] == "DISABLED"
    assert baseline["snmp"] == {"enabled": True, "version": "v3"}
    assert baseline["ntp"] == {"enabled": True, "servers": ["10.50.10.20"], "authentication_enabled": True}
    assert baseline["logging"] == {"syslog_enabled": True, "syslog_hosts": ["10.50.10.30"]}
    assert baseline["banners"]["login_banner_present"] is True


def test_paloalto_hardened_ike_policy():
    baseline = extractor.extract(_demo("paloalto_hardened.conf"), "paloalto")

    assert baseline["crypto"]["ike_policies"] == [{
        "policy_id": None, "encryption": "AES256", "hash_algorithm": "SHA256",
        "dh_group": None, "authentication_method": None,
    }]


# ── paloalto: demo/paloalto_insecure.conf ─────────────────────────────
def test_paloalto_insecure_scalars():
    baseline = extractor.extract(_demo("paloalto_insecure.conf"), "paloalto")

    assert baseline["telnet"]["enabled"] == "ENABLED"
    assert baseline["services"]["http_server_enabled"] == "ENABLED"
    assert baseline["snmp"] == {"enabled": True, "version": "v2c", "community_strings": ["public"]}
    assert baseline["logging"]["syslog_enabled"] is False
    assert "syslog_hosts" not in baseline["logging"]
    assert baseline["banners"]["login_banner_present"] is False


def test_paloalto_insecure_weak_ike_policy():
    baseline = extractor.extract(_demo("paloalto_insecure.conf"), "paloalto")

    assert baseline["crypto"]["ike_policies"] == [{
        "policy_id": None, "encryption": "DES", "hash_algorithm": "MD5",
        "dh_group": None, "authentication_method": None,
    }]


# ── arista: demo/arista_hardened.cfg ──────────────────────────────────
def test_arista_hardened_scalars():
    baseline = extractor.extract(_demo("arista_hardened.cfg"), "arista")

    assert baseline["device"]["raw_hostname"] == "spine-eos-02"
    assert baseline["telnet"]["enabled"] == "DISABLED"
    assert baseline["services"]["http_server_enabled"] == "DISABLED"
    assert baseline["services"]["https_server_enabled"] == "ENABLED"
    assert baseline["snmp"]["enabled"] is True
    assert baseline["snmp"]["version"] == "v3"
    assert baseline["ntp"] == {"authentication_enabled": True, "enabled": True, "servers": ["10.60.10.20"]}
    assert baseline["logging"]["syslog_hosts"] == ["10.60.10.30"]
    assert baseline["banners"]["login_banner_present"] is True


# ── arista: demo/arista_insecure.cfg ──────────────────────────────────
def test_arista_insecure_scalars():
    baseline = extractor.extract(_demo("arista_insecure.cfg"), "arista")

    assert baseline["telnet"]["enabled"] == "ENABLED"
    assert baseline["services"]["http_server_enabled"] == "ENABLED"
    assert "https_server_enabled" not in baseline["services"]
    assert baseline["snmp"]["community_strings"] == ["public"]
    assert baseline["snmp"]["version"] == "v2c"
    assert baseline["banners"]["login_banner_present"] is False
    assert baseline["logging"]["syslog_enabled"] is False
    # No "ntp authenticate" line seen — evidence-only, must abstain rather
    # than assert a confirmed False (see module docstring).
    assert "authentication_enabled" not in baseline["ntp"]
