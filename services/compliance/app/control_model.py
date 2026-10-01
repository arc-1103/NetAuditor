"""
The network as a deterministic discrete-time system, for containment analysis.

State x[k] is a boolean vector over devices: which devices an intruder who holds
the entry device can reach after k routing hops. With A[i][j] = 1 when traffic
can be forwarded from device i to device j (a routing adjacency that is not
filtered), the dynamics are

        x[k+1] = x[k]  OR  (A^T x[k])          x[0] = b   (the entry device)

— the boolean analogue of x[k+1] = A x[k] + b u. The controllability-style
question "can the entry device drive the state to include the core?" is
answered by iterating until the state stops changing (a fixed point, reached in
at most n-1 steps because the state only grows and is bounded by n devices).

The containment numbers come from the same graph: by Menger's theorem the
smallest number of links whose removal (filtering) disconnects the core equals
the maximum number of link-disjoint paths from the entry device, which unit-
capacity max-flow computes exactly. A small number means a few well-placed
filters contain the spread; 0 means the core is already unreachable.

This is an analysis of the routing graph as given (devices and adjacencies);
it does not model per-protocol ACLs or traffic volume.
"""

from collections import deque


def _index(nodes: list[str]) -> dict[str, int]:
    return {node: i for i, node in enumerate(sorted(nodes))}


def step_response(nodes: list[str], edges: list[dict], entry: str, *, removed: set[frozenset[str]] | None = None) -> list[list[str]]:
    """Devices first reached at each step: [[entry], [newly reached at k=1], ...] until the fixed point."""
    removed = removed or set()
    index = _index(nodes)
    n = len(index)
    adjacency = [[False] * n for _ in range(n)]
    for edge in edges:
        a, b = edge["source"], edge["target"]
        if a in index and b in index and frozenset((a, b)) not in removed:
            adjacency[index[a]][index[b]] = adjacency[index[b]][index[a]] = True  # routing adjacency is bidirectional
    names = sorted(index, key=index.get)
    state = [False] * n
    state[index[entry]] = True
    layers = [[entry]]
    while True:
        nxt = state[:]
        for i in range(n):
            if state[i]:
                for j in range(n):
                    if adjacency[i][j]:
                        nxt[j] = True
        fresh = [names[i] for i in range(n) if nxt[i] and not state[i]]
        if not fresh:  # fixed point: x[k+1] == x[k]
            return layers
        layers.append(fresh)
        state = nxt


def min_cut(nodes: list[str], edges: list[dict], source: str, sink: str) -> dict:
    """Edge connectivity between two devices: {"size", "links": [[a, b], ...]} (Edmonds-Karp, unit capacities)."""
    capacity: dict[tuple[str, str], int] = {}
    neighbours: dict[str, set[str]] = {n: set() for n in nodes}
    for edge in edges:
        a, b = edge["source"], edge["target"]
        if a == b or a not in neighbours or b not in neighbours:
            continue
        for u, v in ((a, b), (b, a)):
            capacity[(u, v)] = 1
            neighbours[u].add(v)
    flow = 0
    while True:
        parent = {source: None}
        queue = deque([source])
        while queue and sink not in parent:
            u = queue.popleft()
            for v in sorted(neighbours[u]):
                if v not in parent and capacity.get((u, v), 0) > 0:
                    parent[v] = u
                    queue.append(v)
        if sink not in parent:
            break
        v = sink
        while parent[v] is not None:
            u = parent[v]
            capacity[(u, v)] -= 1
            capacity[(v, u)] = capacity.get((v, u), 0) + 1
            v = u
        flow += 1
    reachable = set(parent)  # source side of the minimum cut
    cut = sorted({tuple(sorted((u, v))) for u in reachable for v in neighbours[u] if v not in reachable})
    return {"size": flow, "links": [list(link) for link in cut]}


def analyze(nodes: list[str], edges: list[dict], entry: str, core: str | None) -> dict:
    layers = step_response(nodes, edges, entry)
    reached = [d for layer in layers for d in layer]
    result = {
        "reach_by_step": [{"step": k, "new": len(layer), "total": sum(len(l) for l in layers[: k + 1]), "devices": layer} for k, layer in enumerate(layers)],
        "reachable": len(reached), "devices": len(nodes), "converged_at_step": len(layers) - 1,
        "steps_to_core": None, "core_reachable": False, "min_cut": None,
    }
    if core:
        for k, layer in enumerate(layers):
            if core in layer:
                result["steps_to_core"], result["core_reachable"] = k, True
                break
        result["min_cut"] = min_cut(nodes, edges, entry, core)
    return result
