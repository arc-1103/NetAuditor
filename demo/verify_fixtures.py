#!/usr/bin/env python3
"""Offline assertions for the deterministic demo fixtures.

This deliberately checks presentation-critical facts without requiring an SLM.
The full integration smoke test compares expected-findings.json to live output.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def require(name: str, snippets: list[str]) -> None:
    text = (ROOT / name).read_text(encoding="utf-8").lower()
    missing = [snippet for snippet in snippets if snippet.lower() not in text]
    if missing:
        raise SystemExit(f"{name}: missing demo evidence {missing}")


require("cisco_insecure.cfg", ["ip ssh version 1", "transport input telnet ssh", "community public", "encryption 3des", "ip http server"])
require("cisco_hardened.cfg", ["ip ssh version 2", "transport input ssh", "snmp-server group", "encryption aes 256", "no ip http server"])
require("fortinet_insecure.conf", ["admin-telnet enable", "allowaccess ping http ssh snmp", 'set name "public"', "proposal des-md5"])
print("All three deterministic demo fixtures contain their expected security evidence.")
