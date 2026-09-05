"""Fail-safe remediation preflight adapter.

The mock performs deterministic lockout checks for local development. A real
Batfish deployment needs a topology/snapshot supplied by the operator; until
that integration is configured, the service returns UNAVAILABLE rather than
claiming an unvalidated change is safe.
"""

import os
import re

import httpx

from app.models import PreflightResult

USE_MOCK = os.getenv("USE_MOCK_BATFISH", "true").lower() == "true"
BATFISH_HOST = os.getenv("BATFISH_HOST", "batfish")
BATFISH_PORT = int(os.getenv("BATFISH_PORT", "9997"))


def static_safety_checks(script: str) -> list[str]:
    flags: list[str] = []
    lowered = script.lower()
    if re.search(r"(^|\n)\s*no\s+username\b", lowered):
        flags.append("Script removes a local administrator account")
    if re.search(r"transport\s+input\s+none", lowered):
        flags.append("Script disables all remote VTY access")
    if re.search(r"^\s*shutdown\s*$", lowered, re.MULTILINE):
        flags.append("Script contains an interface shutdown command")
    if "no ip routing" in lowered:
        flags.append("Script disables IP routing")
    if "<replace_" in lowered:
        flags.append("Script contains a secret placeholder that must be replaced")
    if "! review:" in lowered:
        flags.append("Script contains environment-specific values requiring operator review")
    return flags


async def preflight(script: str) -> PreflightResult:
    flags = static_safety_checks(script)
    if flags:
        return PreflightResult(status="RISK_FLAGS", risk_flags=flags, engine="static-safety")
    if USE_MOCK:
        return PreflightResult(status="SAFE", engine="mock-batfish+static-safety")

    # Batfish's coordinator endpoint proves availability only. Full validation
    # requires an uploaded device/topology snapshot; never convert a health
    # response or connection failure into a SAFE verdict.
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.get(f"http://{BATFISH_HOST}:{BATFISH_PORT}/v2/version")
            response.raise_for_status()
    except (httpx.HTTPError, ValueError) as exc:
        return PreflightResult(
            status="UNAVAILABLE",
            risk_flags=[f"Batfish validation unavailable: {type(exc).__name__}"],
            engine="batfish",
        )
    return PreflightResult(
        status="UNAVAILABLE",
        risk_flags=["Batfish is reachable but no network snapshot was provided"],
        engine="batfish",
    )
