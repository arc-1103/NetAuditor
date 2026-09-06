from __future__ import annotations

import json
import re
from copy import deepcopy
from typing import Any


class InvalidCanonicalTokenError(ValueError):
    """A present model value is not a recognized canonical token or alias."""


def _token(value: Any) -> str:
    return str(value).strip().lower()


def _unknownish(value: Any) -> bool:
    return value is None or (isinstance(value, str) and value.strip().lower() in {"", "unknown", "none"})


VENDOR_ALIASES = {
    "cisco": "cisco",
    "cisco ios": "cisco",
    "cisco ios-xe": "cisco",
    "ios": "cisco",
    "ios-xe": "cisco",
    "juniper": "juniper",
    "junos": "juniper",
    "pan-os": "paloalto",
    "palo alto": "paloalto",
    "paloalto": "paloalto",
    "arista": "arista",
    "arista eos": "arista",
    "eos": "arista",
}

HASH_ALIASES = {
    "md5": "MD5",
    "sha1": "SHA1",
    "sha-1": "SHA1",
    "sha256": "SHA256",
    "sha-256": "SHA256",
    "sha512": "SHA512",
    "sha-512": "SHA512",
    "none": "NONE",
    "unknown": "UNKNOWN",
}

ENCRYPTION_ALIASES = {
    "des": "DES",
    "3des": "3DES",
    "3-des": "3DES",
    "aes128": "AES128",
    "aes-128": "AES128",
    "aes256": "AES256",
    "aes-256": "AES256",
    "chacha20": "CHACHA20",
    "none": "NONE",
    "unknown": "UNKNOWN",
}

PROTOCOL_STATUS_ALIASES = {
    "enabled": "ENABLED",
    "enable": "ENABLED",
    "on": "ENABLED",
    "true": "ENABLED",
    "yes": "ENABLED",
    "disabled": "DISABLED",
    "disable": "DISABLED",
    "off": "DISABLED",
    "false": "DISABLED",
    "no": "DISABLED",
    "unknown": "UNKNOWN",
    "none": "UNKNOWN",
    "": "UNKNOWN",
}

SSH_ALIASES = {
    "ssh1": "1",
    "ssh2": "2",
    "1.0": "1",
    "2.0": "2",
    "1/2": "1-2",
    "none": "none",
    "unknown": "none",
    "": "none",
}

SNMP_ALIASES = {
    "1": "v1",
    "2": "v2c",
    "2c": "v2c",
    "3": "v3",
    "v1": "v1",
    "v2c": "v2c",
    "v3": "v3",
    "none": "none",
    "unknown": "none",
    "": "none",
}


def extract_json(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    text = value.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.I)
        text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start >= 0 and end > start:
            return json.loads(text[start : end + 1])
        raise


def _alias_or_unknown(value: Any, aliases: dict[str, str], field_name: str) -> str:
    if _unknownish(value):
        return aliases.get("unknown", "UNKNOWN")
    key = _token(value)
    try:
        return aliases[key]
    except KeyError as exc:
        raise InvalidCanonicalTokenError(
            f"invalid {field_name} token: {value!r}"
        ) from exc


def normalize_vendor(value: Any) -> str:
    if _unknownish(value):
        return "unknown"
    key = re.sub(r"\s+", " ", _token(value))
    try:
        return VENDOR_ALIASES[key]
    except KeyError as exc:
        raise InvalidCanonicalTokenError(f"invalid detected_vendor token: {value!r}") from exc


def normalize_hash(value: Any) -> str:
    return _alias_or_unknown(value, HASH_ALIASES, "hash algorithm")


def normalize_encryption(value: Any) -> str:
    return _alias_or_unknown(value, ENCRYPTION_ALIASES, "encryption algorithm")


def normalize_protocol_status(value: Any) -> str:
    if isinstance(value, bool):
        return "ENABLED" if value else "DISABLED"
    if _unknownish(value):
        return "UNKNOWN"
    key = _token(value)
    try:
        return PROTOCOL_STATUS_ALIASES[key]
    except KeyError as exc:
        raise InvalidCanonicalTokenError(f"invalid protocol status token: {value!r}") from exc


def normalize_ssh_version(value: Any) -> str:
    if _unknownish(value):
        return "none"
    key = _token(value)
    if key in {"1", "2", "1-2"}:
        return key
    try:
        return SSH_ALIASES[key]
    except KeyError as exc:
        raise InvalidCanonicalTokenError(f"invalid SSH version token: {value!r}") from exc


def normalize_snmp_version(value: Any) -> str:
    if _unknownish(value):
        return "none"
    key = _token(value)
    try:
        return SNMP_ALIASES[key]
    except KeyError as exc:
        raise InvalidCanonicalTokenError(f"invalid SNMP version token: {value!r}") from exc


def normalize_candidate(candidate: Any) -> dict[str, Any]:
    data = deepcopy(extract_json(candidate))
    if not isinstance(data, dict):
        raise ValueError("SLM output must decode to an object")

    if "device" not in data or not isinstance(data["device"], dict):
        raise ValueError("SLM output must contain a device object")

    device = data["device"]
    if "detected_vendor" in device:
        device["detected_vendor"] = normalize_vendor(device["detected_vendor"])

    if "aaa" in data and isinstance(data["aaa"], dict) and "password_encryption" in data["aaa"]:
        data["aaa"]["password_encryption"] = normalize_protocol_status(data["aaa"]["password_encryption"])

    if "ssh" in data and isinstance(data["ssh"], dict) and "version" in data["ssh"]:
        data["ssh"]["version"] = normalize_ssh_version(data["ssh"]["version"])

    if "telnet" in data and isinstance(data["telnet"], dict) and "enabled" in data["telnet"]:
        data["telnet"]["enabled"] = normalize_protocol_status(data["telnet"]["enabled"])

    if "snmp" in data and isinstance(data["snmp"], dict):
        if "version" in data["snmp"]:
            data["snmp"]["version"] = normalize_snmp_version(data["snmp"]["version"])
        if "auth_protocol" in data["snmp"]:
            data["snmp"]["auth_protocol"] = normalize_hash(data["snmp"]["auth_protocol"])
        if "priv_protocol" in data["snmp"]:
            data["snmp"]["priv_protocol"] = normalize_encryption(data["snmp"]["priv_protocol"])

    if "ntp" in data and isinstance(data["ntp"], dict) and "peer_auth_key_hash" in data["ntp"]:
        data["ntp"]["peer_auth_key_hash"] = normalize_hash(data["ntp"]["peer_auth_key_hash"])

    crypto = data.get("crypto")
    if isinstance(crypto, dict):
        policies = crypto.get("ike_policies", [])
        if not isinstance(policies, list):
            raise ValueError("crypto.ike_policies must be a list")
        for policy in policies:
            if not isinstance(policy, dict):
                raise ValueError("each crypto.ike_policies item must be an object")
            if "encryption" in policy:
                policy["encryption"] = normalize_encryption(policy["encryption"])
            if "hash_algorithm" in policy:
                policy["hash_algorithm"] = normalize_hash(policy["hash_algorithm"])

    services = data.get("services")
    if isinstance(services, dict):
        for key in (
            "http_server_enabled", "https_server_enabled", "cdp_enabled",
            "lldp_enabled", "finger_service_enabled", "ip_source_route_enabled",
            "proxy_arp_enabled", "ip_directed_broadcast", "tcp_small_servers",
            "udp_small_servers",
        ):
            if key in services:
                services[key] = normalize_protocol_status(services[key])

    return data
