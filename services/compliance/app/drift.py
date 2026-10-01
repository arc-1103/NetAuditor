"""
Configuration drift for one device across its sequential audits.

Given every evaluated run of the same device (oldest first) and the failing
findings of each, answers the auditor's question: when did a control that now
fails stop passing, and what changed between consecutive audits. Pure logic —
app/db.py supplies the rows, app/main.py serves the result.
"""

from app.risk_scorer import summarize


def build_history(runs: list[dict], current_run_id: str) -> dict:
    """`runs`: oldest first, each {run_id, created_at, filename, findings:[{control_id, severity, title}]}.

    Returns the timeline up to and including `current_run_id` (later audits of
    the device are history too, but "since when" is asked from the current one).
    """
    ids = [run["run_id"] for run in runs]
    if current_run_id not in ids:
        return {"runs": [], "transitions": [], "control_streaks": {}}
    runs = runs[: ids.index(current_run_id) + 1]

    timeline = []
    for run in runs:
        failing = sorted({f["control_id"] for f in run["findings"] if f.get("control_id")})
        timeline.append({
            "run_id": run["run_id"],
            "created_at": run["created_at"],
            "filename": run.get("filename"),
            "failing": failing,
            "compliance_score": summarize(run["findings"])["compliance_score"],
        })

    transitions = []
    for previous, current in zip(timeline, timeline[1:]):
        before, after = set(previous["failing"]), set(current["failing"])
        transitions.append({
            "run_id": current["run_id"],
            "created_at": current["created_at"],
            "introduced": sorted(after - before),
            "resolved": sorted(before - after),
            "score_change": current["compliance_score"] - previous["compliance_score"],
        })

    streaks = {}
    last = timeline[-1]
    for control_id in last["failing"]:
        start = len(timeline) - 1
        while start > 0 and control_id in timeline[start - 1]["failing"]:
            start -= 1
        streaks[control_id] = {
            "failing_since_run": timeline[start]["run_id"],
            "failing_since": timeline[start]["created_at"],
            "audits_failing": len(timeline) - start,
            "last_passed_run": timeline[start - 1]["run_id"] if start > 0 else None,
            "first_audit_of_device": start == 0,
        }
    return {"runs": timeline, "transitions": transitions, "control_streaks": streaks}


# Fields that change on every parse and say nothing about the device's config.
_VOLATILE = {
    "device.config_sha256", "device.parsing_confidence", "device.unknown_blocks_count",
    "device.mean_logprob", "device.reverse_translation_fidelity", "device.parser_agreement",
}
# Baseline fields each control reads (mirrors generic_level1.rego), so the
# diff can mark which changes are the ones that matter for this control.
CONTROL_FIELDS = {
    "CIS-NET-1.1.1": ("ssh.version",),
    "CIS-NET-1.1.2": ("telnet",),
    "CIS-NET-1.1.3": ("ssh.management_acl", "ssh.enabled"),
    "CIS-NET-1.2.1": ("snmp.version", "snmp.enabled"),
    "CIS-NET-1.2.2": ("snmp.community_strings",),
    "CIS-NET-1.3.1": ("crypto.ike_policies",),
    "CIS-NET-1.4.1": ("ntp",),
    "CIS-NET-1.5.1": ("aaa.password_encryption",),
    "CIS-NET-1.6.1": ("banners",),
    "CIS-NET-1.7.1": ("services.http_server_enabled",),
    "CIS-NET-1.8.1": ("logging",),
}


def baseline_diff(old: dict | None, new: dict | None, control_id: str | None = None, *, limit: int = 80) -> list[dict]:
    """Field-level changes between two normalized baselines, the ones that
    bear on `control_id` first. Lists and scalars are compared whole."""
    changes: list[dict] = []
    related_prefixes = CONTROL_FIELDS.get(control_id or "", ())

    def walk(path: str, before, after) -> None:
        if isinstance(before, dict) and after is None:
            after = {}
        elif isinstance(after, dict) and before is None:
            before = {}
        if isinstance(before, dict) and isinstance(after, dict):
            for key in sorted(set(before) | set(after)):
                walk(f"{path}.{key}" if path else key, before.get(key), after.get(key))
        elif before != after and path not in _VOLATILE:
            changes.append({
                "path": path, "before": before, "after": after,
                "related": any(path == p or path.startswith(p + ".") for p in related_prefixes),
            })

    walk("", old or {}, new or {})
    changes.sort(key=lambda change: (not change["related"], change["path"]))
    return changes[:limit]
