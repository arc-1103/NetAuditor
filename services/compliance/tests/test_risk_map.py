from app.risk_map import build_risk_map, shortest_path


def device(i, host):
    return {"id": i, "kind": "device", "hostname": host, "vendor": "cisco", "ip": None}


GRAPH = {
    "nodes": [device("edge", "edge-sw1"), device("dist", "dist-sw1"), device("core", "core-rtr1"), device("other", "branch-fw"), device("agg", "agg-sw1")],
    "edges": [{"source": "edge", "target": "dist"}, {"source": "dist", "target": "core"}, {"source": "other", "target": "core"}, {"source": "agg", "target": "core"}],
}
RISK = {
    "edge": {"compliance_score": 30, "critical": 2, "total_findings": 6, "audit_run_id": "r1"},
    "dist": {"compliance_score": 80, "critical": 0, "total_findings": 2, "audit_run_id": "r2"},
    "core": {"compliance_score": 90, "critical": 0, "total_findings": 1, "audit_run_id": "r3"},
    "other": {"compliance_score": 70, "critical": 0, "total_findings": 3, "audit_run_id": "r4"},
    "agg": {"compliance_score": 85, "critical": 0, "total_findings": 1, "audit_run_id": "r5"},
}


def test_weakest_device_is_the_entry_point_and_path_runs_to_the_most_connected_core():
    result = build_risk_map(GRAPH, RISK)
    highlight = result["highlight"]
    assert highlight["entry_point"] == "edge" and highlight["core"] == "core"
    assert highlight["path"] == ["edge", "dist", "core"]
    labels = {n["id"]: n["label"] for n in result["nodes"]}
    assert labels["edge"] == "edge-sw1"
    assert next(n for n in result["nodes"] if n["id"] == "core")["connections"] == 3


def test_no_path_is_invented_between_disconnected_devices():
    split = {"nodes": GRAPH["nodes"], "edges": [{"source": "edge", "target": "dist"}, {"source": "other", "target": "core"}, {"source": "agg", "target": "core"}]}
    result = build_risk_map(split, RISK)
    assert result["highlight"]["path"] is None and "no routing path" in result["note"]


def test_unaudited_or_single_device_graphs_say_so_instead_of_drawing_a_path():
    assert build_risk_map({"nodes": [], "edges": []}, {})["highlight"] is None
    single = {"nodes": [device("edge", "e")], "edges": []}
    assert build_risk_map(single, RISK)["highlight"] is None
    assert build_risk_map(GRAPH, {})["highlight"] is None


def test_unresolved_peers_are_shown_but_never_chosen_as_entry_or_core():
    graph = {"nodes": GRAPH["nodes"] + [{"id": "peer:10.9.9.9", "kind": "unresolved", "ip": "10.9.9.9", "hostname": None, "vendor": None}],
             "edges": GRAPH["edges"] + [{"source": "core", "target": "peer:10.9.9.9"}, {"source": "dist", "target": "peer:10.9.9.9"}]}
    result = build_risk_map(graph, RISK)
    assert result["highlight"]["core"] in {"core", "dist"} and result["highlight"]["entry_point"] == "edge"
    assert any(n["id"] == "peer:10.9.9.9" and n["label"] == "10.9.9.9" for n in result["nodes"])


def test_shortest_path_is_shortest():
    edges = [{"source": "a", "target": "b"}, {"source": "b", "target": "c"}, {"source": "c", "target": "d"}, {"source": "a", "target": "d"}]
    assert shortest_path(edges, "a", "d") == ["a", "d"]
    assert shortest_path(edges, "a", "zzz") is None


def test_risk_map_carries_the_state_space_containment_analysis():
    control = build_risk_map(GRAPH, RISK)["control"]
    assert control["core_reachable"] and control["steps_to_core"] == 2
    assert control["min_cut"]["size"] == 1  # edge-sw1 hangs off a single uplink to dist-sw1
    assert control["min_cut"]["links"] == [["dist", "edge"]] or control["min_cut"]["links"] == [["edge", "dist"]]
    assert control["reachable"] == control["devices"] == 5
