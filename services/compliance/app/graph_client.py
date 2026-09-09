"""
GraphRAG topology client.

Maps each evaluated baseline's interfaces and routing neighbors
(contracts/security_baseline.schema.json `topology`) into a Neo4j graph, and
answers "blast radius" queries: which other devices are reachable from a
device that just failed a control, by walking the routing adjacency the
graph has learned across every audit run so far.

Optional enrichment, not a compliance gate — the same resilience pattern
services/parsing/app/rag.py and vendor_fingerprint.py already use for their
own optional providers. A Neo4j outage must not turn an evaluatable baseline
into a failed compliance run; app/evaluator.py degrades to blast_radius: []
when this raises.

Device identity: every `Device` node is keyed by `config_sha256` — the same
id `blast_radius()` returns and the id contracts/compliance_finding.schema.json
promises. A routing neighbor is only known by its IP until (if ever) some
scanned device turns out to own that IP on one of its interfaces. Until
then it is parked on an `UnresolvedPeer {ip: ...}` node — a distinct label,
never a `Device` — so it can never be mistaken for a real device id.
`_write_topology`'s reconciliation step redirects every `ROUTES_TO` edge
pointing at an `UnresolvedPeer` onto the real `Device` node as soon as one
is ingested for that IP, and drops the placeholder. A neighbor genuinely
never scanned stays an `UnresolvedPeer` forever, correctly dead-ending
blast-radius traversal there rather than reporting it as a device.
"""

from __future__ import annotations

import os
from typing import Any, Protocol


class TopologyGraphProvider(Protocol):
    async def ingest(self, baseline: dict[str, Any]) -> None:
        """Merge one baseline's device/interface/adjacency facts into the graph."""
        ...

    async def blast_radius(self, device_id: str, *, max_hops: int) -> list[str]:
        """Ids of devices reachable from `device_id` within `max_hops` of
        routing adjacency, excluding `device_id` itself."""
        ...


class EmptyTopologyGraphProvider:
    """Safe default: Compliance works when Neo4j is unavailable or unconfigured."""

    async def ingest(self, baseline: dict[str, Any]) -> None:
        return None

    async def blast_radius(self, device_id: str, *, max_hops: int) -> list[str]:
        return []


class Neo4jTopologyGraphProvider:
    def __init__(self, uri: str, user: str, password: str):
        from neo4j import AsyncGraphDatabase

        self._driver = AsyncGraphDatabase.driver(uri, auth=(user, password))

    async def close(self) -> None:
        await self._driver.close()

    async def ingest(self, baseline: dict[str, Any]) -> None:
        device = baseline.get("device") or {}
        device_id = device.get("config_sha256")
        if not device_id:
            return

        topology = baseline.get("topology") or {}
        interfaces = topology.get("interfaces") or []
        neighbors = topology.get("routing_neighbors") or []

        async with self._driver.session() as session:
            await session.execute_write(self._write_topology, device_id, device, interfaces, neighbors)

    @staticmethod
    async def _write_topology(
        tx,
        device_id: str,
        device: dict[str, Any],
        interfaces: list[dict[str, Any]],
        neighbors: list[dict[str, Any]],
    ) -> None:
        await tx.run(
            """
            MERGE (d:Device {id: $device_id})
            SET d.vendor = $vendor, d.os = $os, d.hostname = $hostname
            """,
            device_id=device_id,
            vendor=device.get("detected_vendor"),
            os=device.get("detected_os"),
            hostname=device.get("raw_hostname"),
        )

        own_ips: list[str] = []
        for iface in interfaces:
            name = iface.get("name")
            if not name:
                continue
            ip_address = iface.get("ip_address")
            if ip_address:
                own_ips.append(ip_address)
            await tx.run(
                """
                MATCH (d:Device {id: $device_id})
                MERGE (i:Interface {device_id: $device_id, name: $name})
                SET i.ip_address = $ip_address, i.description = $description
                MERGE (d)-[:HAS_INTERFACE]->(i)
                """,
                device_id=device_id,
                name=name,
                ip_address=ip_address,
                description=iface.get("description"),
            )

        for neighbor in neighbors:
            neighbor_ip = neighbor.get("neighbor_ip")
            if not neighbor_ip:
                continue
            await tx.run(
                """
                MATCH (d:Device {id: $device_id})
                OPTIONAL MATCH (peer:Device)-[:HAS_INTERFACE]->(:Interface {ip_address: $neighbor_ip})
                FOREACH (_ IN CASE WHEN peer IS NOT NULL THEN [1] ELSE [] END |
                    MERGE (d)-[:ROUTES_TO {protocol: $protocol}]->(peer)
                )
                FOREACH (_ IN CASE WHEN peer IS NULL THEN [1] ELSE [] END |
                    MERGE (u:UnresolvedPeer {ip: $neighbor_ip})
                    MERGE (d)-[:ROUTES_TO {protocol: $protocol}]->(u)
                )
                """,
                device_id=device_id,
                neighbor_ip=neighbor_ip,
                protocol=neighbor.get("protocol") or "unknown",
            )

        # Reconciliation: this device's own interfaces may be the answer to
        # an earlier device's routing_neighbors that had no matching device
        # yet, parked on a placeholder UnresolvedPeer keyed by IP. Redirect
        # every ROUTES_TO edge pointing at that placeholder onto this real
        # Device, then drop the placeholder — this is what keeps
        # blast_radius() returning real Device ids instead of bare IPs, and
        # what lets multi-hop traversal actually continue past a peer once
        # it has been scanned.
        if own_ips:
            await tx.run(
                """
                MATCH (d:Device {id: $device_id})
                UNWIND $own_ips AS ip
                MATCH (u:UnresolvedPeer {ip: ip})
                MATCH (caller:Device)-[r:ROUTES_TO]->(u)
                WHERE caller.id <> $device_id
                MERGE (caller)-[:ROUTES_TO {protocol: r.protocol}]->(d)
                DELETE r
                WITH DISTINCT u
                WHERE NOT (u)<-[:ROUTES_TO]-()
                DETACH DELETE u
                """,
                device_id=device_id,
                own_ips=own_ips,
            )

    async def blast_radius(self, device_id: str, *, max_hops: int) -> list[str]:
        async with self._driver.session() as session:
            return await session.execute_read(self._read_blast_radius, device_id, max_hops)

    @staticmethod
    async def _read_blast_radius(tx, device_id: str, max_hops: int) -> list[str]:
        # max_hops is interpolated into the query text rather than bound as a
        # parameter because Cypher's variable-length path bounds must be
        # literals. It always comes from GRAPH_BLAST_RADIUS_MAX_HOPS
        # (services/compliance/.env.example), never from request input, so
        # this is not an injection surface — int() still guards it.
        query = (
            f"MATCH (d:Device {{id: $device_id}})-[:ROUTES_TO*1..{int(max_hops)}]-(n:Device) "
            "RETURN DISTINCT n.id AS id"
        )
        cursor = await tx.run(query, device_id=device_id)
        records = [record async for record in cursor]
        return sorted(record["id"] for record in records if record["id"] != device_id)


def build_topology_graph_provider() -> TopologyGraphProvider:
    """NEO4J_URI unset means Neo4j isn't configured for this environment
    (e.g. running the service standalone per the README) — fall back to the
    no-op provider rather than failing at import time."""
    uri = os.getenv("NEO4J_URI")
    if not uri:
        return EmptyTopologyGraphProvider()
    return Neo4jTopologyGraphProvider(
        uri,
        os.getenv("NEO4J_USER", "neo4j"),
        os.getenv("NEO4J_PASSWORD", ""),
    )
