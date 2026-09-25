"""
Counterfactual Compliance Engine — docs/Suggestions.md item 3.

Answers "what happens if I apply this fix?" before anything is approved or
applied: evaluates a proposed (modified) baseline the same way a real
upload would be scored, without persisting it, then diffs the result
against the current evaluated state. Built by composing machinery this
codebase already has — OPA evaluation (app/opa_client.py), the weighted
compliance formula (app/risk_scorer.py, docs/Additional-Features.md §1),
and the ACL reachability diff (app/reachability_diff.py, §4) — this module
adds no new evaluation logic of its own.

Deliberately calls app/opa_client.evaluate() directly rather than
app/evaluator.evaluate_baseline(): that function's GraphRAG/anomaly
enrichment (graph_provider.ingest, anomaly_provider.ingest) are real,
persistent side effects meant for a genuine device scan — writing a
hypothetical "what if I applied this fix" baseline into the topology graph
or the anomaly-detection peer corpus would permanently pollute both with a
device that never existed. A counterfactual must stay a pure read.

Like app/reachability_diff.py, this does not synthesize the "proposed"
baseline from a remediation script's CLI text itself — the caller supplies
both baselines, the same "before/after, caller supplies both sides" shape
the ACL diff already uses.
"""

from app.reachability_diff import diff_acl, diff_topology
from app.risk_scorer import SEVERITY_ORDER, score_findings, summarize

_EMPTY_ACL: dict = {"ingress_entries": [], "egress_entries": []}
_EMPTY_TOPOLOGY: dict = {"interfaces": [], "routing_neighbors": []}


def _introduced_risk_tier(proposed_findings: list[dict], introduced_ids: set[str], opens_new_access: bool, compliance_regressed: bool) -> str:
    """docs/Suggestions.md item 3's example output shows a LOW/MEDIUM/HIGH
    risk tier, not just a binary verdict. Reuses the same severity vocabulary
    app/risk_scorer.py already scores every finding with — no new severity
    scale — picking the worst-of: the highest severity among the findings
    this change would newly introduce, bumped one tier if it also opens
    network access the current config didn't permit, since a new violation
    *and* a new reachable flow compounds the exposure the doc's own example
    warns about."""
    introduced_severities = [
        str(f.get("severity", "")).upper() for f in proposed_findings if f.get("control_id") in introduced_ids
    ]
    worst = next((s for s in SEVERITY_ORDER if s in introduced_severities), None)
    if worst in ("CRITICAL", "HIGH"):
        tier = "HIGH"
    elif worst == "MEDIUM" or compliance_regressed:
        tier = "MEDIUM"
    else:
        tier = "LOW"
    if opens_new_access and tier == "LOW":
        tier = "MEDIUM"
    elif opens_new_access and tier == "MEDIUM":
        tier = "HIGH"
    return tier


def counterfactual(
    current_findings: list[dict], proposed_findings: list[dict],
    current_acl: dict | None, proposed_acl: dict | None,
    current_topology: dict | None = None, proposed_topology: dict | None = None,
) -> dict:
    current_findings = score_findings(current_findings)
    proposed_findings = score_findings(proposed_findings)
    current_summary = summarize(current_findings)
    proposed_summary = summarize(proposed_findings)

    reachability = None
    if current_acl is not None or proposed_acl is not None:
        reachability = diff_acl(current_acl or _EMPTY_ACL, proposed_acl or _EMPTY_ACL)
    blast_radius = None
    if current_topology is not None or proposed_topology is not None:
        blast_radius = diff_topology(current_topology or _EMPTY_TOPOLOGY, proposed_topology or _EMPTY_TOPOLOGY)

    current_ids = {f["control_id"] for f in current_findings if f.get("control_id")}
    proposed_ids = {f["control_id"] for f in proposed_findings if f.get("control_id")}
    violations_introduced = proposed_ids - current_ids

    # docs/Suggestions.md's own example: an improved compliance score alone
    # doesn't make a change SAFE — opening a flow the current config
    # doesn't permit is a risk even if the fix also resolves violations.
    compliance_regressed = proposed_summary["compliance_score"] < current_summary["compliance_score"]
    opens_new_access = bool(reachability) and (
        reachability["ingress"]["newly_permitted_flows"] or reachability["egress"]["newly_permitted_flows"]
    )

    return {
        "current": current_summary,
        "proposed": proposed_summary,
        "compliance_delta": proposed_summary["compliance_score"] - current_summary["compliance_score"],
        "violations_resolved": sorted(current_ids - proposed_ids),
        "violations_introduced": sorted(violations_introduced),
        "reachability": reachability,
        "blast_radius": blast_radius,
        "risk": _introduced_risk_tier(proposed_findings, violations_introduced, opens_new_access, compliance_regressed),
        "verdict": "RISK_FLAG" if (compliance_regressed or opens_new_access) else "SAFE",
    }
