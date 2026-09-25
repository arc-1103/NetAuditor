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

from app.reachability_diff import diff_acl
from app.risk_scorer import score_findings, summarize

_EMPTY_ACL: dict = {"ingress_entries": [], "egress_entries": []}


def counterfactual(current_findings: list[dict], proposed_findings: list[dict], current_acl: dict | None, proposed_acl: dict | None) -> dict:
    current_findings = score_findings(current_findings)
    proposed_findings = score_findings(proposed_findings)
    current_summary = summarize(current_findings)
    proposed_summary = summarize(proposed_findings)

    reachability = None
    if current_acl is not None or proposed_acl is not None:
        reachability = diff_acl(current_acl or _EMPTY_ACL, proposed_acl or _EMPTY_ACL)

    current_ids = {f["control_id"] for f in current_findings if f.get("control_id")}
    proposed_ids = {f["control_id"] for f in proposed_findings if f.get("control_id")}

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
        "violations_introduced": sorted(proposed_ids - current_ids),
        "reachability": reachability,
        "verdict": "RISK_FLAG" if (compliance_regressed or opens_new_access) else "SAFE",
    }
