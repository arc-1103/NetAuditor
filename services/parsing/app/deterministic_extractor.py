"""
Deterministic (TextFSM) cross-check extractor — docs/action.md Phase 1,
building docs/Suggestions.md item 7 (the AI Interpretation Trust Layer's
"TextFSM: ..." half of its own mockup).

Extracts a partial SecurityBaseline-shaped dict directly from raw config
text, independent of the SLM path in this same service. Used only to
cross-check the SLM's own extraction (app/agreement.py, Phase 2) — never
fed to Compliance on its own, so a wrong or incomplete template here can
only ever make the trust-layer signal less useful, never make wrong data
look trusted.

Vendor/field coverage: services/parsing/textfsm_templates/ has templates
per vendor with an existing demo/*.cfg fixture (cisco today; fortinet,
juniper, paloalto, arista follow the same pattern — see docs/action.md's
phase sequencing). A field a vendor's templates can't yet extract is
absent from the returned dict, never a guessed/default value — "no
signal" and "wrong" must never be confused for a trust layer whose whole
job is telling operators which is which.

Fail-open/fail-closed split on absence mirrors
services/compliance/policies/generic/generic_level1.rego's own documented
split exactly: login-banner presence and remote-syslog configuration are
the two controls that Rego bundle treats as "directly observable, fail
closed on absence" (their absence over the whole file is itself confirmed
evidence). Everything else (ssh/telnet/snmp/ntp/crypto/http/https/aaa) is
vendor-dependent and evidence-only, matching Rego's fail-open treatment —
no match means "we don't know," not "confirmed absent."
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

import textfsm

TEMPLATE_DIR = Path(__file__).parents[1] / "textfsm_templates"


class DeterministicExtractorProvider(Protocol):
    def extract(self, config_text: str, vendor: str) -> dict:
        """Return a partial SecurityBaseline-shaped dict. Absent keys mean
        "no signal," never a default/guessed value."""
        ...


class EmptyDeterministicExtractorProvider:
    """Safe default — an unsupported vendor, or the feature disabled via
    ENABLE_DETERMINISTIC_CROSSCHECK=false, abstains on every field."""

    def extract(self, config_text: str, vendor: str) -> dict:
        return {}


def _run_template(name: str, config_text: str) -> list[dict]:
    """Runs one .textfsm template, returns every non-empty row as a dict.
    Rows where every captured value is falsy (e.g. a Record fired by a
    block-boundary marker like "!" with nothing captured yet) are dropped
    here rather than by every caller — see decision_table-style templates
    under textfsm_templates/ for why those extra empty rows exist at all."""
    path = TEMPLATE_DIR / name
    with path.open(encoding="utf-8") as f:
        fsm = textfsm.TextFSM(f)
    rows = fsm.ParseText(config_text)
    results = []
    for row in rows:
        record = dict(zip(fsm.header, row))
        if any(v for v in record.values()):
            results.append(record)
    return results


def _protocol_status(on: str, off: str) -> str | None:
    if on:
        return "ENABLED"
    if off:
        return "DISABLED"
    return None


def _set(baseline: dict, path: str, value) -> None:
    """Sets a dotted path (e.g. "ssh.version") on a nested dict, creating
    intermediate section dicts as needed. A value of None/[]/"" is a
    no-op — "no evidence" must never become a present-but-empty key,
    which would look like positive evidence of "nothing configured"."""
    if value in (None, "", []):
        return
    node = baseline
    parts = path.split(".")
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value


_CISCO_ENCRYPTION = {
    "des": "DES", "3des": "3DES",
    "aes": "AES128", "aes 128": "AES128", "aes 256": "AES256",
}
_CISCO_HASH = {
    "md5": "MD5", "sha": "SHA1", "sha1": "SHA1", "sha256": "SHA256", "sha512": "SHA512",
}
_SNMP_VERSION = {"1": "v1", "2c": "v2c", "3": "v3"}


def _extract_cisco(config_text: str) -> dict:
    baseline: dict = {}
    scalar_rows = _run_template("cisco_scalars.textfsm", config_text)
    scalars = scalar_rows[0] if scalar_rows else {}

    _set(baseline, "device.raw_hostname", scalars.get("HOSTNAME"))
    _set(baseline, "aaa.password_encryption",
         _protocol_status(scalars.get("PASSWORD_ENCRYPTION_ON", ""), scalars.get("PASSWORD_ENCRYPTION_OFF", "")))

    ssh_version = scalars.get("SSH_VERSION")
    if ssh_version:
        _set(baseline, "ssh.enabled", True)
        _set(baseline, "ssh.version", ssh_version)
    _set(baseline, "ssh.management_acl", scalars.get("MGMT_ACL"))

    telnet_transport = scalars.get("TELNET_TRANSPORT")
    if telnet_transport:
        _set(baseline, "telnet.enabled", "ENABLED" if "telnet" in telnet_transport.split() else "DISABLED")

    _set(baseline, "services.http_server_enabled",
         _protocol_status(scalars.get("HTTP_ON", ""), scalars.get("HTTP_OFF", "")))
    _set(baseline, "services.https_server_enabled",
         _protocol_status(scalars.get("HTTPS_ON", ""), scalars.get("HTTPS_OFF", "")))

    # Fail-closed on absence — matches generic_level1.rego's own two
    # "directly observable" exceptions (see module docstring).
    _set(baseline, "banners.login_banner_present", bool(scalars.get("BANNER_LOGIN")))
    _set(baseline, "ntp.authentication_enabled", bool(scalars.get("NTP_AUTH")))

    ntp_servers = scalars.get("NTP_SERVER") or []
    if ntp_servers:
        _set(baseline, "ntp.enabled", True)
        _set(baseline, "ntp.servers", ntp_servers)

    syslog_hosts = scalars.get("SYSLOG_HOST") or []
    _set(baseline, "logging.syslog_enabled", bool(syslog_hosts))
    _set(baseline, "logging.syslog_hosts", syslog_hosts)
    if scalars.get("LOGGING_BUFFERED"):
        _set(baseline, "logging.local_buffer_enabled", True)

    community_strings = scalars.get("SNMP_COMMUNITY") or []
    snmp_host_version = scalars.get("SNMP_HOST_VERSION")
    snmp_v3 = scalars.get("SNMP_V3")
    if community_strings or snmp_host_version or snmp_v3:
        _set(baseline, "snmp.enabled", True)
    _set(baseline, "snmp.community_strings", community_strings)
    if snmp_v3:
        _set(baseline, "snmp.version", "v3")
    elif snmp_host_version:
        _set(baseline, "snmp.version", _SNMP_VERSION.get(snmp_host_version, snmp_host_version))

    ike_rows = _run_template("cisco_ike_policies.textfsm", config_text)
    if ike_rows:
        _set(baseline, "crypto.ike_policies", [
            {
                "policy_id": int(r["POLICY_ID"]) if r.get("POLICY_ID") else None,
                "encryption": _CISCO_ENCRYPTION.get((r.get("ENCRYPTION") or "").lower(), "UNKNOWN"),
                "hash_algorithm": _CISCO_HASH.get((r.get("HASH") or "").lower(), "UNKNOWN"),
                "dh_group": int(r["DH_GROUP"]) if r.get("DH_GROUP") else None,
                "authentication_method": r.get("AUTH_METHOD") or None,
            }
            for r in ike_rows
        ])

    acl_rows = _run_template("cisco_acl_entries.textfsm", config_text)
    if acl_rows:
        _set(baseline, "acl.ingress_acl_name", acl_rows[0].get("ACL_NAME"))
        _set(baseline, "acl.ingress_acl_applied", True)
        _set(baseline, "acl.ingress_entries", [
            {
                "sequence": None,
                "action": r["ACTION"],
                "protocol": "ip",
                "source": r["NETWORK"],
                "destination": "any",
                "port": None,
            }
            for r in acl_rows
        ])

    interface_rows = _run_template("cisco_interfaces.textfsm", config_text)
    if interface_rows:
        _set(baseline, "topology.interfaces", [
            {
                "name": r["NAME"],
                "ip_address": r.get("IP") or None,
                "subnet_mask": r.get("MASK") or None,
                "description": r.get("DESCRIPTION") or None,
                "enabled": not bool(r.get("SHUTDOWN")),
            }
            for r in interface_rows
        ])

    neighbor_rows = _run_template("cisco_routing_neighbors.textfsm", config_text)
    if neighbor_rows:
        _set(baseline, "topology.routing_neighbors", [
            {
                "protocol": "bgp",
                "neighbor_ip": r.get("NEIGHBOR_IP") or None,
                "remote_asn": int(r["REMOTE_ASN"]) if r.get("REMOTE_ASN") else None,
                "local_asn": int(r["LOCAL_ASN"]) if r.get("LOCAL_ASN") else None,
            }
            for r in neighbor_rows
        ])

    return baseline


_FORTINET_ENCRYPTION = {
    "des": "DES", "3des": "3DES", "aes128": "AES128", "aes256": "AES256",
}
_FORTINET_HASH = {"md5": "MD5", "sha1": "SHA1", "sha256": "SHA256", "sha512": "SHA512"}


def _extract_fortinet(config_text: str) -> dict:
    baseline: dict = {}
    rows = _run_template("fortinet_scalars.textfsm", config_text)
    scalars = rows[0] if rows else {}

    _set(baseline, "device.raw_hostname", scalars.get("HOSTNAME"))

    admin_telnet = scalars.get("ADMIN_TELNET")
    if admin_telnet:
        _set(baseline, "telnet.enabled", "ENABLED" if admin_telnet == "enable" else "DISABLED")

    community_strings = scalars.get("SNMP_COMMUNITY_NAME") or []
    snmp_user = scalars.get("SNMP_USER_PRESENT")
    snmp_sysinfo = scalars.get("SNMP_SYSINFO_STATUS")
    if community_strings or snmp_user or snmp_sysinfo == "enable":
        _set(baseline, "snmp.enabled", True)
    _set(baseline, "snmp.community_strings", community_strings)
    if snmp_user:
        _set(baseline, "snmp.version", "v3")
    elif community_strings:
        # FortiOS's community-string config doesn't distinguish v1 from
        # v2c in the fixtures this template covers — v2c is the common
        # default; flag this as the approximation it is rather than
        # silently asserting certainty this template doesn't have.
        _set(baseline, "snmp.version", "v2c")

    ike_proposal = scalars.get("IKE_PROPOSAL")
    if ike_proposal:
        policies = []
        for token in ike_proposal.split():
            enc, _, hash_part = token.partition("-")
            policies.append({
                "policy_id": None,
                "encryption": _FORTINET_ENCRYPTION.get(enc.lower(), "UNKNOWN"),
                "hash_algorithm": _FORTINET_HASH.get(hash_part.lower(), "UNKNOWN"),
                "dh_group": None,
                "authentication_method": None,
            })
        _set(baseline, "crypto.ike_policies", policies)

    # Fail-closed on absence — matches generic_level1.rego's own two
    # "directly observable" exceptions (see module docstring).
    _set(baseline, "banners.login_banner_present", bool(scalars.get("BANNER_BUFFER")))
    syslog_status = scalars.get("SYSLOG_STATUS")
    _set(baseline, "logging.syslog_enabled", syslog_status == "enable")
    syslog_server = scalars.get("SYSLOG_SERVER")
    if syslog_server:
        _set(baseline, "logging.syslog_hosts", [syslog_server])

    return baseline


def _extract_juniper(config_text: str) -> dict:
    baseline: dict = {}
    rows = _run_template("juniper_scalars.textfsm", config_text)
    scalars = rows[0] if rows else {}

    _set(baseline, "device.raw_hostname", scalars.get("HOSTNAME"))

    ssh_services_seen = bool(scalars.get("SSH_SERVICES_SEEN"))
    if scalars.get("TELNET") == "telnet":
        _set(baseline, "telnet.enabled", "ENABLED")
    elif ssh_services_seen:
        # The "set system services" block is in use and no telnet line
        # appeared in it — positive evidence of absence, not just silence.
        _set(baseline, "telnet.enabled", "DISABLED")
    if ssh_services_seen:
        _set(baseline, "ssh.enabled", True)

    if scalars.get("HTTP_SERVICES") == "http":
        _set(baseline, "services.http_server_enabled", "ENABLED")
    elif ssh_services_seen:
        _set(baseline, "services.http_server_enabled", "DISABLED")

    _set(baseline, "aaa.password_encryption",
         _protocol_status(scalars.get("PASSWORD_ENC_ON", ""), scalars.get("PASSWORD_ENC_OFF", "")))

    community_strings = sorted(set(scalars.get("SNMP_COMMUNITY") or []))
    snmp_v3_user = scalars.get("SNMP_V3_USER")
    if community_strings or snmp_v3_user:
        _set(baseline, "snmp.enabled", True)
    _set(baseline, "snmp.community_strings", community_strings)
    if snmp_v3_user:
        _set(baseline, "snmp.version", "v3")
    elif community_strings:
        _set(baseline, "snmp.version", "v2c")  # same approximation as Fortinet — see its comment

    ntp_servers = scalars.get("NTP_SERVER") or []
    if ntp_servers:
        _set(baseline, "ntp.enabled", True)
        _set(baseline, "ntp.servers", ntp_servers)
    if scalars.get("NTP_AUTH_KEY"):
        _set(baseline, "ntp.authentication_enabled", True)

    # Fail-closed on absence — matches generic_level1.rego's own two
    # "directly observable" exceptions (see module docstring).
    _set(baseline, "banners.login_banner_present", bool(scalars.get("LOGIN_MESSAGE")))
    syslog_hosts = scalars.get("SYSLOG_HOST") or []
    _set(baseline, "logging.syslog_enabled", bool(syslog_hosts))
    _set(baseline, "logging.syslog_hosts", syslog_hosts)

    return baseline


_PALOALTO_ENCRYPTION = {
    "des": "DES", "3des": "3DES", "aes-128-cbc": "AES128", "aes-256-cbc": "AES256",
}
_PALOALTO_HASH = {"md5": "MD5", "sha1": "SHA1", "sha256": "SHA256", "sha384": "UNKNOWN", "sha512": "SHA512"}


def _extract_paloalto(config_text: str) -> dict:
    baseline: dict = {}
    rows = _run_template("paloalto_scalars.textfsm", config_text)
    scalars = rows[0] if rows else {}

    _set(baseline, "device.raw_hostname", scalars.get("HOSTNAME"))

    telnet_disable = scalars.get("TELNET_DISABLE")
    if telnet_disable:
        _set(baseline, "telnet.enabled", "DISABLED" if telnet_disable == "yes" else "ENABLED")

    http_disable = scalars.get("HTTP_DISABLE")
    if http_disable:
        _set(baseline, "services.http_server_enabled", "DISABLED" if http_disable == "yes" else "ENABLED")

    ike_encryption = scalars.get("IKE_ENCRYPTION")
    ike_hash = scalars.get("IKE_HASH")
    if ike_encryption or ike_hash:
        _set(baseline, "crypto.ike_policies", [{
            "policy_id": None,
            "encryption": _PALOALTO_ENCRYPTION.get((ike_encryption or "").lower(), "UNKNOWN"),
            "hash_algorithm": _PALOALTO_HASH.get((ike_hash or "").lower(), "UNKNOWN"),
            "dh_group": None,
            "authentication_method": None,
        }])

    ntp_server = scalars.get("NTP_SERVER")
    if ntp_server:
        _set(baseline, "ntp.enabled", True)
        _set(baseline, "ntp.servers", [ntp_server])
    if scalars.get("NTP_AUTH"):
        _set(baseline, "ntp.authentication_enabled", True)

    snmp_version = scalars.get("SNMP_VERSION")
    snmp_community = scalars.get("SNMP_COMMUNITY")
    if snmp_version:
        _set(baseline, "snmp.enabled", True)
        _set(baseline, "snmp.version", snmp_version)
    if snmp_community:
        _set(baseline, "snmp.community_strings", [snmp_community])

    # Fail-closed on absence — matches generic_level1.rego's own two
    # "directly observable" exceptions (see module docstring).
    _set(baseline, "banners.login_banner_present", bool(scalars.get("LOGIN_BANNER")))
    syslog_server = scalars.get("SYSLOG_SERVER_IP")
    syslog_disable = scalars.get("SYSLOG_DISABLE")
    if syslog_server:
        _set(baseline, "logging.syslog_enabled", True)
        _set(baseline, "logging.syslog_hosts", [syslog_server])
    elif syslog_disable == "yes":
        _set(baseline, "logging.syslog_enabled", False)
    else:
        _set(baseline, "logging.syslog_enabled", False)  # no syslog-setting block seen at all

    return baseline


def _extract_arista(config_text: str) -> dict:
    baseline: dict = {}
    rows = _run_template("arista_scalars.textfsm", config_text)
    scalars = rows[0] if rows else {}

    _set(baseline, "device.raw_hostname", scalars.get("HOSTNAME"))
    _set(baseline, "telnet.enabled",
         _protocol_status(scalars.get("TELNET_ON", ""), scalars.get("TELNET_OFF", "")))
    _set(baseline, "services.http_server_enabled",
         _protocol_status(scalars.get("HTTP_ON", ""), scalars.get("HTTP_OFF", "")))
    if scalars.get("HTTPS_ON"):
        _set(baseline, "services.https_server_enabled", "ENABLED")

    community_strings = scalars.get("SNMP_COMMUNITY") or []
    snmp_host_version = scalars.get("SNMP_HOST_VERSION")
    snmp_v3 = scalars.get("SNMP_V3")
    if community_strings or snmp_host_version or snmp_v3:
        _set(baseline, "snmp.enabled", True)
    _set(baseline, "snmp.community_strings", community_strings)
    if snmp_v3:
        _set(baseline, "snmp.version", "v3")
    elif snmp_host_version:
        _set(baseline, "snmp.version", _SNMP_VERSION.get(snmp_host_version, snmp_host_version))

    # Fail-closed on absence — matches generic_level1.rego's own two
    # "directly observable" exceptions (see module docstring).
    _set(baseline, "banners.login_banner_present", bool(scalars.get("BANNER_LOGIN")))
    _set(baseline, "ntp.authentication_enabled", bool(scalars.get("NTP_AUTH")))

    ntp_servers = scalars.get("NTP_SERVER") or []
    if ntp_servers:
        _set(baseline, "ntp.enabled", True)
        _set(baseline, "ntp.servers", ntp_servers)

    syslog_hosts = scalars.get("SYSLOG_HOST") or []
    _set(baseline, "logging.syslog_enabled", bool(syslog_hosts))
    _set(baseline, "logging.syslog_hosts", syslog_hosts)
    if scalars.get("LOGGING_BUFFERED"):
        _set(baseline, "logging.local_buffer_enabled", True)

    return baseline


_VENDOR_BUILDERS = {
    "cisco": _extract_cisco,
    "fortinet": _extract_fortinet,
    "juniper": _extract_juniper,
    "paloalto": _extract_paloalto,
    "arista": _extract_arista,
}


class TextFSMExtractor:
    """Real implementation — dispatches to the vendor-specific builder
    above, or abstains entirely (empty dict) for a vendor with no
    templates yet. `vendor` is matched case-insensitively against
    app/vendor_detector.py's `detected_vendor` values."""

    def extract(self, config_text: str, vendor: str) -> dict:
        builder = _VENDOR_BUILDERS.get((vendor or "").lower())
        if builder is None:
            return {}
        return builder(config_text)
