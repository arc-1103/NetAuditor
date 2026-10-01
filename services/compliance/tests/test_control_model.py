from app import control_model as cm


def links(*pairs):
    return [{"source": a, "target": b} for a, b in pairs]


CHAIN = (["e", "d", "c", "x"], links(("e", "d"), ("d", "c")))                      # x is isolated
DIAMOND = (["e", "a", "b", "c"], links(("e", "a"), ("e", "b"), ("a", "c"), ("b", "c")))


def test_state_grows_one_hop_per_step_and_stops_at_a_fixed_point():
    nodes, edges = CHAIN
    layers = cm.step_response(nodes, edges, "e")
    assert layers == [["e"], ["d"], ["c"]]  # 'x' is never reached; the loop terminated


def test_fixed_point_is_reached_in_at_most_n_minus_1_steps_on_any_connected_graph():
    nodes = [f"n{i}" for i in range(9)]
    ring = links(*[(nodes[i], nodes[(i + 1) % 9]) for i in range(9)])
    layers = cm.step_response(nodes, ring, "n0")
    assert len(layers) - 1 <= len(nodes) - 1 and sum(map(len, layers)) == 9


def test_analysis_reports_hops_to_core_and_reach_counts():
    nodes, edges = CHAIN
    result = cm.analyze(nodes, edges, "e", "c")
    assert result["steps_to_core"] == 2 and result["core_reachable"] and result["reachable"] == 3 and result["devices"] == 4
    assert [s["total"] for s in result["reach_by_step"]] == [1, 2, 3]
    assert result["converged_at_step"] == 2


def test_min_cut_is_the_number_of_link_disjoint_paths_and_names_the_links():
    nodes, edges = DIAMOND
    assert cm.min_cut(nodes, edges, "e", "c")["size"] == 2           # two disjoint paths
    chain_nodes, chain_edges = CHAIN
    cut = cm.min_cut(chain_nodes, chain_edges, "e", "c")
    assert cut["size"] == 1 and len(cut["links"]) == 1                # a single link holds the chain together


def test_filtering_the_cut_links_really_isolates_the_core():
    nodes, edges = CHAIN
    cut = cm.min_cut(nodes, edges, "e", "c")
    removed = {frozenset(link) for link in cut["links"]}
    layers = cm.step_response(nodes, edges, "e", removed=removed)
    assert "c" not in [d for layer in layers for d in layer]


def test_removing_one_link_of_a_diamond_does_not_isolate_the_core_but_two_do():
    nodes, edges = DIAMOND
    one = cm.step_response(nodes, edges, "e", removed={frozenset(("e", "a"))})
    assert "c" in [d for layer in one for d in layer]
    both = cm.step_response(nodes, edges, "e", removed={frozenset(("e", "a")), frozenset(("e", "b"))})
    assert "c" not in [d for layer in both for d in layer]


def test_disconnected_core_has_zero_cut_and_is_not_reachable():
    nodes, edges = CHAIN
    result = cm.analyze(nodes, edges, "e", "x")
    assert result["core_reachable"] is False and result["steps_to_core"] is None and result["min_cut"]["size"] == 0
