"""Fail-safe remediation preflight adapter.

Two deterministic layers run before (and instead of, until it's configured)
real Batfish: static_safety_checks() (regex lockout patterns) and
app/reachability_fallback.py (docs/Additional-Features.md §4's ACL/route
diffing, invoked here as `_reachability_flags`). A real Batfish deployment
needs a topology/snapshot supplied by the operator; until that integration
is configured, the service returns UNAVAILABLE rather than claiming an
unvalidated change is safe.
"""

import os
import re

import httpx

from app.models import PreflightResult
from app.reachability_fallback import estimate_reachability_impact

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


def _reachability_flags(script: str) -> list[str]:
    """docs/Additional-Features.md §4's demo-safe fallback: only
    `newly_permitted` findings are escalated here — a change *widening*
    management/ACL reachability is the surprising direction worth blocking
    on, unlike narrowing (routine for a compliance fix) which
    reachability_fallback.py already declines to over-report. See that
    module's docstring for why only removals have a knowable direction."""
    estimate = estimate_reachability_impact(script)
    return [f"Reachability fallback: {finding}" for finding in estimate.newly_permitted]


async def preflight(script: str) -> PreflightResult:
    flags = static_safety_checks(script)
    reachability_flags = _reachability_flags(script)
    if reachability_flags:
        flags = [*flags, *reachability_flags]
    if flags:
        engine = "static-safety+reachability-fallback" if reachability_flags else "static-safety"
        return PreflightResult(status="RISK_FLAGS", risk_flags=flags, engine=engine)
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
