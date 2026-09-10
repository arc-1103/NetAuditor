"""Deterministically attach sanitized source lines to policy findings."""
from __future__ import annotations

import re

CONTROL_PATTERNS = {
    "CIS-NET-1.1.1": (r"\bip\s+ssh\s+version\s+(?:1|1-2)\b",),
    "CIS-NET-1.1.2": (r"transport\s+input\b.*\btelnet\b", r"admin-telnet\s+enable"),
    "CIS-NET-1.1.3": (r"access-class\s+", r"trustedhosts"),
    "CIS-NET-1.2.1": (r"snmp.*(?:v1|v2c|version\s+2c)", r"config\s+system\s+snmp\s+community"),
    "CIS-NET-1.2.2": (r"snmp.*community", r"set\s+name\s+"),
    "CIS-NET-1.3.1": (r"\b(?:encryption|proposal)\b.*\b(?:des|3des)\b",),
    "CIS-NET-1.4.1": (r"\bntp\s+server\b", r"config\s+system\s+ntp"),
    "CIS-NET-1.5.1": (r"no\s+service\s+password-encryption",),
    "CIS-NET-1.6.1": (r"\bbanner\s+(?:login|motd)\b",),
    "CIS-NET-1.7.1": (r"\bip\s+http\s+server\b", r"allowaccess\b.*\bhttp\b", r"admin-port\s+80"),
    "CIS-NET-1.8.1": (r"\blogging\s+(?:buffered|console|monitor)\b", r"log\s+syslogd.*status\s+disable"),
}


def locate(control_id: str, source_text: str, *, limit: int = 3) -> list[dict]:
    patterns = CONTROL_PATTERNS.get(control_id, ())
    matches = []
    for number, line in enumerate(source_text.splitlines(), start=1):
        if any(re.search(pattern, line, re.IGNORECASE) for pattern in patterns):
            matches.append({"line": number, "text": line.strip()[:240]})
            if len(matches) >= limit:
                break
    return matches


def attach(findings: list[dict], source_text: str | None) -> list[dict]:
    return [
        {**finding, "source_lines": locate(finding.get("control_id", ""), source_text) if source_text else []}
        for finding in findings
    ]
