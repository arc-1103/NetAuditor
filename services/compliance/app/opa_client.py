"""
Thin HTTP client for the OPA server.

Evaluates a normalized SecurityBaseline (contracts/security_baseline.schema.json)
against the policy bundle and returns raw findings
(contracts/compliance_finding.schema.json, minus the fields added later by
risk_scorer/db).

One call evaluates the whole `data.compliance.<framework>` subtree rather than
one package at a time, so adding a vendor means dropping a .rego file into
policies/ — no Python change. The cost is that every package sees every
device, which is why each one guards on input.device.detected_vendor.
"""

import os
from typing import Any

import httpx

# Base of OPA's data API, e.g. http://opa:8181/v1/data
OPA_URL = os.getenv("OPA_URL", "http://opa:8181/v1/data").rstrip("/")
DEFAULT_FRAMEWORK = os.getenv("DEFAULT_FRAMEWORK", "CIS")
OPA_TIMEOUT_SECONDS = float(os.getenv("OPA_TIMEOUT_SECONDS", "10"))

SUPPORTED_FRAMEWORKS = {"CIS", "NIST", "STIG"}


class OPAEvaluationError(RuntimeError):
    """OPA could not be reached, or returned something unusable.

    Raised rather than swallowed: a compliance engine that silently returns
    "no findings" when the policy engine is down reports a broken device as
    compliant, which is the one failure this lane must never have.
    """


def policy_path(framework: str) -> str:
    """Map a framework name to its OPA data path."""
    fw = framework.upper()
    if fw not in SUPPORTED_FRAMEWORKS:
        raise ValueError(f"Unknown framework '{framework}'. Expected one of {sorted(SUPPORTED_FRAMEWORKS)}")
    return f"{OPA_URL}/compliance/{fw.lower()}"


def collect_findings(node: Any) -> list[dict]:
    """Walk OPA's nested result document and gather every package's `deny` set.

    OPA returns the subtree shape, e.g.
        {"cisco_ios": {"level1": {"deny": [...], "applies": true}}}
    so anything not under a "deny" key (helper rules like `applies`) is ignored.
    """
    findings: list[dict] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "deny" and isinstance(value, list):
                findings.extend(f for f in value if isinstance(f, dict))
            else:
                findings.extend(collect_findings(value))
    return findings


async def evaluate(baseline: dict, framework: str | None = None) -> list[dict]:
    """Evaluate one baseline against a framework's policy bundle.

    Returns findings sorted by control_id so two runs over the same config
    produce byte-identical output — the audit trail depends on it.
    """
    url = policy_path(framework or DEFAULT_FRAMEWORK)

    try:
        async with httpx.AsyncClient(timeout=OPA_TIMEOUT_SECONDS) as client:
            resp = await client.post(url, json={"input": baseline})
    except httpx.HTTPError as e:
        raise OPAEvaluationError(f"OPA request to {url} failed: {e}") from e

    if resp.status_code >= 400:
        raise OPAEvaluationError(f"OPA returned {resp.status_code} for {url}: {resp.text}")

    # An undefined path is `{}` with no "result" key — that means the bundle
    # for this framework isn't loaded, not that the device is clean.
    body = resp.json()
    if "result" not in body:
        raise OPAEvaluationError(
            f"No policy bundle loaded at {url}. Check POLICY_BUNDLE_PATH and that "
            f"the opa container was started with `run --server /policies`."
        )

    return sorted(collect_findings(body["result"]), key=lambda f: f.get("control_id", ""))
