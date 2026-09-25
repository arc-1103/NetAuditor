"""
Deterministic ACL/route reachability diff — docs/Additional-Features.md §4.

A lighter-weight blast-radius estimator that doesn't require full topology
modeling: diffs the flows an ACL permits before vs. after a proposed
change, using the same ACLConfig/ACLEntry shape Parsing already normalizes
every vendor's config into (contracts/security_baseline.schema.json's `acl`
object — see services/schema/schema/security_baseline.py). This is
explicitly a narrower, best-effort estimate compared to GraphRAG's
multi-hop topology reachability (app/graph_client.py) or a real Batfish
simulation — it can only ever see the ACL it's handed, not what's beyond
the next hop. docs/Additional-Features.md §4 recommends keeping it
permanently as a fast first-pass filter regardless, with Batfish invoked
only for changes this flags as non-trivial.

This module only diffs two already-parsed ACLConfig-shaped structures; it
does not parse remediation CLI text into an ACL itself — that would
duplicate services/parsing's job and reintroduce the vendor-specific CLI
parsing this codebase's generic Rego bundle was built to avoid. A caller
(a UI preview, a future automation) supplies both sides explicitly.
"""

Flow = tuple[str, str, str, str]  # (protocol, source, destination, port)


def _flow_key(entry: dict) -> Flow:
    return (
        str(entry.get("protocol", "")).lower(),
        str(entry.get("source", "")).lower(),
        str(entry.get("destination", "")).lower(),
        str(entry.get("port") or "any").lower(),
    )


def _entry_key(entry: dict) -> tuple:
    """Identity for "was this exact line touched", not just "does it permit
    the same flow" — a rule that changes from permit to deny for the same
    flow is a real edit even though _flow_key alone wouldn't show it as a
    new line."""
    return (entry.get("sequence"), str(entry.get("action", "")).lower(), *_flow_key(entry))


def _diff_side(before_entries: list[dict], after_entries: list[dict]) -> dict:
    before_permitted = {_flow_key(e) for e in before_entries if str(e.get("action", "")).lower() == "permit"}
    after_permitted = {_flow_key(e) for e in after_entries if str(e.get("action", "")).lower() == "permit"}
    newly_blocked = before_permitted - after_permitted
    newly_permitted = after_permitted - before_permitted

    before_lines = {_entry_key(e) for e in before_entries}
    after_lines = {_entry_key(e) for e in after_entries}
    lines_touched = len(before_lines ^ after_lines)

    services_referenced = sorted({f"{proto}/{port}" for proto, _, _, port in (newly_blocked | newly_permitted)})

    return {
        "newly_blocked_flows": [{"protocol": p, "source": s, "destination": d, "port": port} for p, s, d, port in sorted(newly_blocked)],
        "newly_permitted_flows": [{"protocol": p, "source": s, "destination": d, "port": port} for p, s, d, port in sorted(newly_permitted)],
        "acl_lines_touched": lines_touched,
        "services_referenced": services_referenced,
    }


def diff_acl(before: dict, after: dict) -> dict:
    """before/after: ACLConfig-shaped dicts (ingress_entries/egress_entries
    lists of ACLEntry dicts, plus the *_acl_name/_acl_applied fields).
    Returns an approximate blast radius: which side changed, how many lines,
    which flows, which services — everything docs/Additional-Features.md §4
    asks the fallback to report, at the ACL-diff level of detail rather
    than multi-hop topology."""
    ingress = _diff_side(before.get("ingress_entries", []), after.get("ingress_entries", []))
    egress = _diff_side(before.get("egress_entries", []), after.get("egress_entries", []))

    interfaces_touched = []
    if ingress["acl_lines_touched"] or ingress["newly_blocked_flows"] or ingress["newly_permitted_flows"]:
        interfaces_touched.append({"side": "ingress", "acl_name": after.get("ingress_acl_name") or before.get("ingress_acl_name")})
    if egress["acl_lines_touched"] or egress["newly_blocked_flows"] or egress["newly_permitted_flows"]:
        interfaces_touched.append({"side": "egress", "acl_name": after.get("egress_acl_name") or before.get("egress_acl_name")})

    return {
        "ingress": ingress,
        "egress": egress,
        "interfaces_touched": interfaces_touched,
        "acl_lines_touched": ingress["acl_lines_touched"] + egress["acl_lines_touched"],
        "services_referenced": sorted(set(ingress["services_referenced"]) | set(egress["services_referenced"])),
        "has_reachability_change": bool(
            ingress["newly_blocked_flows"] or ingress["newly_permitted_flows"]
            or egress["newly_blocked_flows"] or egress["newly_permitted_flows"]
        ),
    }
