"""
Fleet topology with risk overlaid, and the path from the riskiest device to the
core — for the executive dashboard.

This is plain graph analysis, not machine learning: it joins the routing
topology (Neo4j) with each device's audit result, picks the device with the
weakest compliance posture as the "entry point", picks the most-connected
device as the "core", and finds the shortest routing path between them by
breadth-first search. That path is the route an attacker who compromised the
weak device would most directly take toward the core; it is a structural
indication, not a prediction of behaviour.
"""

from collections import deque

from app import control_model


def _risk(entry: dict | None) -> float:
    """Higher = weaker posture. Unscored devices rank below any scored one."""
    if not entry:
        return -1.0
    return (100 - entry["compliance_score"]) + 5 * entry.get("critical", 0) + 0.1 * entry.get("total_findings", 0)


def shortest_path(edges: list[dict], start: str, goal: str) -> list[str] | None:
    neighbours: dict[str, set[str]] = {}
    for edge in edges:
        neighbours.setdefault(edge["source"], set()).add(edge["target"])
        neighbours.setdefault(edge["target"], set()).add(edge["source"])
    queue, previous = deque([start]), {start: None}
    while queue:
        node = queue.popleft()
        if node == goal:
            path = []
            while node is not None:
                path.append(node)
                node = previous[node]
            return path[::-1]
        for nxt in sorted(neighbours.get(node, ())):
            if nxt not in previous:
                previous[nxt] = node
                queue.append(nxt)
    return None


def build_risk_map(graph: dict, risk_by_device: dict[str, dict]) -> dict:
    """graph: {"nodes": [{id, kind, hostname, vendor, ip}], "edges": [{source, target, protocol}]}."""
    devices = [n for n in graph["nodes"] if n["kind"] == "device"]
    if not devices:
        return {"nodes": [], "edges": [], "highlight": None, "note": "No routing topology is known yet."}

    degree: dict[str, int] = {}
    for edge in graph["edges"]:
        for end in (edge["source"], edge["target"]):
            degree[end] = degree.get(end, 0) + 1

    nodes = []
    for node in graph["nodes"]:
        entry = risk_by_device.get(node["id"])
        nodes.append({
            **node,
            "label": node.get("hostname") or (node.get("ip") if node["kind"] != "device" else node["id"][:8]),
            "compliance_score": entry["compliance_score"] if entry else None,
            "findings": entry["total_findings"] if entry else None,
            "audit_run_id": entry["audit_run_id"] if entry else None,
            "connections": degree.get(node["id"], 0),
        })

    scored = [d for d in devices if risk_by_device.get(d["id"])]
    if not scored or len(devices) < 2:
        return {"nodes": nodes, "edges": graph["edges"], "highlight": None,
                "note": "Need at least two audited devices connected by routing to trace a path."}

    entry_point = max(scored, key=lambda d: (_risk(risk_by_device[d["id"]]), d["id"]))
    core = max((d for d in devices if d["id"] != entry_point["id"]), key=lambda d: (degree.get(d["id"], 0), d["id"]), default=None)
    path = shortest_path(graph["edges"], entry_point["id"], core["id"]) if core else None
    device_ids = [d["id"] for d in devices]
    analysis = control_model.analyze(device_ids, graph["edges"], entry_point["id"], core["id"] if core else None)
    return {
        "nodes": nodes, "edges": graph["edges"],
        "highlight": {"entry_point": entry_point["id"], "core": core["id"] if core else None, "path": path,
                      "entry_reason": "weakest compliance posture", "core_reason": "most-connected device"},
        "control": analysis,
        "note": None if path else "The weakest device has no routing path to the core device.",
    }
