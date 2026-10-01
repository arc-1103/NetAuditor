"""
Firmware-aware remediation guidance for the PDF report.

A rule says: for this vendor (and optionally only this OS version range), a
failing control needs this extra note. Rules are plain data so an operator can
extend them for the platforms they run, and they are the only place a report's
advice changes with the device's software version. Nothing here alters a
control's pass/fail verdict or severity — those stay with the OPA policy.

version ranges compare the leading dotted numbers ("15.3(3)M" -> (15, 3)).
`min_version` is inclusive, `max_version` exclusive; omit either for no bound.
"""

import re
from typing import Any

RULES: list[dict[str, Any]] = [
    {
        "vendor": "cisco", "control_id": "CIS-NET-1.1.1",
        "note": "SSH version 2 needs an RSA key of at least 768 bits and a domain name; generate it first "
                "(`ip domain-name <name>` then `crypto key generate rsa modulus 2048`) or `ip ssh version 2` will not take effect.",
    },
    {
        "vendor": "cisco", "control_id": "CIS-NET-1.5.1", "min_version": "15.3",
        "note": "`service password-encryption` only applies reversible type 7 obfuscation. On this release, also store secrets "
                "with a strong hash: `enable algorithm-type scrypt secret <password>` and `username <name> algorithm-type scrypt secret <password>`.",
    },
    {
        "vendor": "cisco", "control_id": "CIS-NET-1.5.1", "max_version": "15.3",
        "note": "This release predates scrypt secrets (added in 15.3); use type 5 secrets (`enable secret`) where possible "
                "and plan a software upgrade to reach a stronger hash.",
    },
]


def _parse(version: str | None) -> tuple[int, ...]:
    match = re.match(r"\s*v?(\d+(?:\.\d+)*)", version or "")
    return tuple(int(part) for part in match.group(1).split(".")) if match else ()


def _applies(rule: dict[str, Any], vendor: str, version: str | None) -> bool:
    if rule["vendor"] != vendor:
        return False
    if "min_version" not in rule and "max_version" not in rule:
        return True
    parsed = _parse(version)
    if not parsed:
        return False  # a version-bounded note is only shown when the version is known
    if "min_version" in rule and parsed < _parse(rule["min_version"]):
        return False
    if "max_version" in rule and parsed >= _parse(rule["max_version"]):
        return False
    return True


def guidance_for(device: dict[str, Any], findings: list[dict]) -> dict[str, list[str]]:
    """{control_id: [notes]} for the failing controls that have a matching rule."""
    vendor = (device.get("vendor") or "").lower()
    version = device.get("os_version")
    failing = {f["control_id"] for f in findings if f.get("control_id")}
    notes: dict[str, list[str]] = {}
    for rule in RULES:
        if rule["control_id"] in failing and _applies(rule, vendor, version):
            notes.setdefault(rule["control_id"], []).append(rule["note"])
    return notes
