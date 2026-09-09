"""
Unit tests for app.graph_client against a fake Neo4j driver/session/
transaction — no real Neo4j needed. Mirrors the fake-httpx-client approach
services/parsing/tests/test_slm.py uses for Ollama.
"""

import pytest

from app import graph_client
from app.graph_client import EmptyTopologyGraphProvider, Neo4jTopologyGraphProvider, build_topology_graph_provider

BASELINE = {
    "device": {
        "config_sha256": "a" * 64,
        "detected_vendor": "cisco",
        "detected_os": "IOS-XE",
        "raw_hostname": "EDGE-RTR",
    },
    "topology": {
        "interfaces": [
            {"name": "GigabitEthernet0/0", "ip_address": "10.0.0.1", "description": "uplink"},
            {"ip_address": "10.0.0.2"},  # no name — must be skipped
        ],
        "routing_neighbors": [
            {"protocol": "bgp", "neighbor_ip": "10.0.0.2"},
            {"protocol": "ospf"},  # no neighbor_ip — must be skipped
        ],
    },
}


class FakeCursor:
    def __init__(self, records):
        self._records = records

    def __aiter__(self):
        return self._generator()

    async def _generator(self):
        for record in self._records:
            yield record


class FakeTransaction:
    def __init__(self, query_results=None):
        self.queries: list[tuple[str, dict]] = []
        self._query_results = query_results or []

    async def run(self, query, **params):
        self.queries.append((query, params))
        return FakeCursor(self._query_results)


class FakeSession:
    def __init__(self, tx):
        self.tx = tx

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def execute_write(self, fn, *args):
        return await fn(self.tx, *args)

    async def execute_read(self, fn, *args):
        return await fn(self.tx, *args)


class FakeDriver:
    def __init__(self, session):
        self._session = session

    def session(self):
        return self._session


def _provider(tx: FakeTransaction) -> Neo4jTopologyGraphProvider:
    provider = Neo4jTopologyGraphProvider.__new__(Neo4jTopologyGraphProvider)
    provider._driver = FakeDriver(FakeSession(tx))
    return provider


# ── EmptyTopologyGraphProvider ───────────────────────────────────────
async def test_empty_provider_ingest_is_a_noop():
    assert await EmptyTopologyGraphProvider().ingest(BASELINE) is None


async def test_empty_provider_blast_radius_is_empty():
    assert await EmptyTopologyGraphProvider().blast_radius("x", max_hops=3) == []


# ── Neo4jTopologyGraphProvider.ingest ────────────────────────────────
async def test_ingest_merges_device_interface_and_neighbor():
    tx = FakeTransaction()
    await _provider(tx).ingest(BASELINE)

    queries = [q for q, _ in tx.queries]
    assert any("MERGE (d:Device" in q for q in queries)
    assert any("MERGE (i:Interface" in q for q in queries)
    assert any("MERGE (d)-[:ROUTES_TO" in q for q in queries)

    device_params = next(p for q, p in tx.queries if "SET d.vendor" in q)
    assert device_params == {
        "device_id": "a" * 64,
        "vendor": "cisco",
        "os": "IOS-XE",
        "hostname": "EDGE-RTR",
    }

    interface_params = next(p for q, p in tx.queries if "MERGE (i:Interface" in q)
    assert interface_params["name"] == "GigabitEthernet0/0"
    assert interface_params["ip_address"] == "10.0.0.1"

    neighbor_query, neighbor_params = next((q, p) for q, p in tx.queries if "MERGE (d)-[:ROUTES_TO" in q)
    assert neighbor_params == {"device_id": "a" * 64, "neighbor_ip": "10.0.0.2", "protocol": "bgp"}
    # Both branches must be in the one statement: resolve to a real scanned
    # peer if one owns this IP, otherwise park it on a placeholder that is
    # never mistaken for a Device id.
    assert "peer:Device" in neighbor_query
    assert "UnresolvedPeer" in neighbor_query


async def test_ingest_reconciles_unresolved_peers_that_match_this_devices_ips():
    tx = FakeTransaction()
    await _provider(tx).ingest(BASELINE)

    reconcile_query, reconcile_params = next(
        (q, p) for q, p in tx.queries if "UnresolvedPeer" in q and "DETACH DELETE" in q
    )
    assert reconcile_params == {"device_id": "a" * 64, "own_ips": ["10.0.0.1"]}
    assert "MATCH (caller:Device)-[r:ROUTES_TO]->(u)" in reconcile_query


async def test_ingest_skips_reconciliation_when_no_interface_has_an_ip():
    tx = FakeTransaction()
    await _provider(tx).ingest(
        {
            "device": {"config_sha256": "b" * 64, "detected_vendor": "cisco"},
            "topology": {"interfaces": [{"name": "Gi0/0"}], "routing_neighbors": []},
        }
    )

    assert not any("DETACH DELETE" in q for q, _ in tx.queries)


async def test_ingest_skips_interfaces_without_a_name_and_neighbors_without_an_ip():
    tx = FakeTransaction()
    await _provider(tx).ingest(BASELINE)

    interface_queries = [p for q, p in tx.queries if "MERGE (i:Interface" in q]
    neighbor_queries = [p for q, p in tx.queries if "MERGE (d)-[:ROUTES_TO" in q]
    assert len(interface_queries) == 1
    assert len(neighbor_queries) == 1


async def test_ingest_does_nothing_without_a_config_sha256():
    tx = FakeTransaction()
    await _provider(tx).ingest({"device": {}, "topology": {}})

    assert tx.queries == []


# ── Neo4jTopologyGraphProvider.blast_radius ──────────────────────────
async def test_blast_radius_excludes_the_source_device_and_sorts_results():
    tx = FakeTransaction(query_results=[{"id": "z" * 64}, {"id": "a" * 64}, {"id": "m" * 64}])
    result = await _provider(tx).blast_radius("a" * 64, max_hops=3)

    assert result == ["m" * 64, "z" * 64]


async def test_blast_radius_embeds_max_hops_as_a_query_literal():
    tx = FakeTransaction(query_results=[])
    await _provider(tx).blast_radius("a" * 64, max_hops=5)

    query, params = tx.queries[0]
    assert "*1..5" in query
    assert params == {"device_id": "a" * 64}


# ── build_topology_graph_provider ────────────────────────────────────
def test_build_returns_empty_provider_when_neo4j_uri_unset(monkeypatch):
    monkeypatch.delenv("NEO4J_URI", raising=False)

    assert isinstance(build_topology_graph_provider(), EmptyTopologyGraphProvider)


def test_build_returns_neo4j_provider_when_configured(monkeypatch):
    monkeypatch.setenv("NEO4J_URI", "bolt://neo4j:7687")
    monkeypatch.setenv("NEO4J_USER", "neo4j")
    monkeypatch.setenv("NEO4J_PASSWORD", "secret")

    calls = []

    class FakeAsyncGraphDatabase:
        @staticmethod
        def driver(uri, auth):
            calls.append((uri, auth))
            return "fake-driver"

    monkeypatch.setattr("neo4j.AsyncGraphDatabase", FakeAsyncGraphDatabase)

    provider = build_topology_graph_provider()

    assert isinstance(provider, Neo4jTopologyGraphProvider)
    assert calls == [("bolt://neo4j:7687", ("neo4j", "secret"))]
