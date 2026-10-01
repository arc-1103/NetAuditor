"""
Loads a demo fleet so every screen has something to show. Run inside the compliance
container (it uses the real evaluator, OPA, database and topology graph):

    docker exec -i netaudit-compliance-1 python - < demo/seed_demo.py

It is idempotent only in the sense that it adds more data each run; start from a clean
database (`docker compose down -v`) for a tidy demo. Everything it writes is ordinary
application data except the dated history (backdated timestamps) and the synthetic
Monday violation events, which exist to give the cycle analysis something to find.
"""

import asyncio
import copy
import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import text

from app import anomaly_client, db, evaluator, graph_client

NOW = datetime.now(timezone.utc).replace(microsecond=0)
REMEDIATION = os.getenv("REMEDIATION_URL", "http://remediation:8004")
SELF = "http://localhost:8002"


def sha(*parts) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()


def iface(name, ip, mask="255.255.255.252"):
    return {"name": name, "ip_address": ip, "subnet_mask": mask, "enabled": True}


def neighbor(ip, protocol="ospf", asn=None):
    return {"protocol": protocol, "neighbor_ip": ip, "remote_asn": asn}


# posture overrides on top of a compliant baseline
POSTURES = {
    "clean": {},
    "snmp": {"snmp": {"enabled": True, "version": "v2c", "community_strings": ["corp-ro", "public"]}},
    "core_now": {
        "snmp": {"enabled": True, "version": "v2c", "community_strings": ["corp-ro", "public"]},
        "ssh": {"enabled": True, "version": "2", "management_acl": None},
        "ntp": {"enabled": True, "authentication_enabled": False},
    },
    "dist": {"telnet": {"enabled": "ENABLED"}, "banners": {"login_banner_present": False}, "logging": {"syslog_enabled": False, "syslog_hosts": []}},
    "edge_bad": {
        "telnet": {"enabled": "ENABLED"}, "ssh": {"enabled": True, "version": "1", "management_acl": None},
        "snmp": {"enabled": True, "version": "v2c", "community_strings": ["public", "private"]},
        "crypto": {"ike_policies": [{"policy_id": "10", "encryption": "3DES", "hash": "SHA1", "dh_group": 2}]},
        "ntp": {"enabled": True, "authentication_enabled": False}, "aaa": {"password_encryption": "DISABLED"},
        "banners": {"login_banner_present": False}, "services": {"http_server_enabled": "ENABLED"},
        "logging": {"syslog_enabled": False, "syslog_hosts": []},
    },
    "branch": {"services": {"http_server_enabled": "ENABLED"}, "banners": {"login_banner_present": False}},
    "jun": {"logging": {"syslog_enabled": False, "syslog_hosts": []}, "banners": {"login_banner_present": False}},
    "pa_clean": {},
}

FLEET = {
    "core-rtr1": dict(vendor="cisco", os="IOS-XE", version="17.6.3", model="C9500-24Y4C", serial="FCW2341L0AB",
                      ifaces=[iface("GigabitEthernet0/0", "10.1.0.1"), iface("GigabitEthernet0/1", "10.1.0.5"), iface("GigabitEthernet0/2", "10.1.0.9"),
                              iface("GigabitEthernet0/3", "10.1.0.13"), iface("GigabitEthernet0/4", "192.168.50.1", "255.255.255.0")],
                      neighbors=[neighbor("10.1.0.2"), neighbor("10.1.0.6", "bgp", 65010), neighbor("10.1.0.10", "bgp", 65020), neighbor("10.1.0.14", "bgp", 65030)]),
    "dist-sw1": dict(vendor="cisco", os="IOS-XE", version="16.12.4", model="C9300-48P", serial="FOC2250X1CD",
                     ifaces=[iface("GigabitEthernet0/0", "10.1.0.2"), iface("GigabitEthernet0/1", "10.1.1.1")],
                     neighbors=[neighbor("10.1.0.1"), neighbor("10.1.1.2")]),
    "edge-sw1": dict(vendor="cisco", os="IOS", version="15.0(2)SE11", model="WS-C2960-24TT-L", serial="FCQ1234Y0EF",
                     ifaces=[iface("GigabitEthernet0/1", "10.1.1.2")], neighbors=[neighbor("10.1.1.1")]),
    "branch-fw": dict(vendor="fortinet", os="FortiOS", version="7.2.5", model="FGT60F", serial="FGT60FTK21045678",
                      ifaces=[iface("port1", "10.1.0.6")], neighbors=[neighbor("10.1.0.5", "bgp", 65001)]),
    "jun-edge": dict(vendor="juniper", os="JunOS", version="21.4R3", model="MX204", serial="JN12A5B2CAFA",
                     ifaces=[iface("ge-0/0/0", "10.1.0.10")], neighbors=[neighbor("10.1.0.9", "bgp", 65001)]),
    "pa-fw": dict(vendor="paloalto", os="PAN-OS", version="10.2.4", model="PA-440", serial="0123456789AB",
                  ifaces=[iface("ethernet1/1", "10.1.0.14")], neighbors=[neighbor("10.1.0.13", "bgp", 65001)]),
}

CONFIG_LINES = {
    "telnet": "line vty 0 4\n transport input telnet ssh",
    "ssh_v1": "ip ssh version 1",
    "snmp_public": "snmp-server community public RO\nsnmp-server community private RW",
    "ike_3des": "crypto isakmp policy 10\n encryption 3des\n hash sha\n group 2",
    "ntp": "ntp server 10.9.9.9",
    "no_pw_enc": "no service password-encryption",
    "http": "ip http server",
    "nosyslog": "! no logging host configured",
}


def baseline(host: str, posture: str, tag: str) -> dict:
    spec = FLEET[host]
    base = {
        "device": {"raw_hostname": host, "detected_vendor": spec["vendor"], "detected_os": spec["os"], "detected_os_version": spec["version"],
                   "detected_hardware_model": spec["model"], "serial_number": spec["serial"], "config_sha256": sha(host, tag),
                   "parsing_confidence": 0.95, "unknown_blocks_count": 0, "mean_logprob": -0.21, "reverse_translation_fidelity": 0.92},
        "ssh": {"enabled": True, "version": "2", "management_acl": "MGMT-ONLY"},
        "telnet": {"enabled": "DISABLED"},
        "snmp": {"enabled": True, "version": "v3", "community_strings": []},
        "ntp": {"enabled": True, "authentication_enabled": True},
        "aaa": {"password_encryption": "ENABLED"},
        "banners": {"login_banner_present": True},
        "services": {"http_server_enabled": "DISABLED"},
        "logging": {"syslog_enabled": True, "syslog_hosts": ["10.9.9.20"]},
        "crypto": {"ike_policies": [{"policy_id": "10", "encryption": "AES256", "hash": "SHA256", "dh_group": 14}]},
        "acl": {"ingress_entries": [], "egress_entries": [], "implicit_deny_present": True},
        "topology": {"interfaces": copy.deepcopy(spec["ifaces"]), "routing_neighbors": copy.deepcopy(spec["neighbors"])},
    }
    for section, values in POSTURES[posture].items():
        base[section] = {**base.get(section, {}), **values} if isinstance(values, dict) else values
    return base


def config_text(host: str, posture: str) -> str:
    lines = [f"hostname {host}", "!"]
    flags = {"edge_bad": ["telnet", "ssh_v1", "snmp_public", "ike_3des", "ntp", "no_pw_enc", "http", "nosyslog"],
             "dist": ["telnet", "nosyslog"], "core_now": ["snmp_public", "ntp"], "snmp": ["snmp_public"],
             "branch": ["http"], "jun": ["nosyslog"]}.get(posture, [])
    for flag in flags:
        lines += [CONFIG_LINES[flag], "!"]
    return "\n".join(lines) + "\n"


async def sql(statement: str, **params):
    async with db.async_session() as session, session.begin():
        await session.execute(text(statement), params)


async def add_run(host: str, posture: str, days_ago: int, tag: str, *, live: bool, trend_anchor: bool = False) -> str:
    run_id = str(uuid.uuid4())
    spec, when = FLEET[host], NOW - timedelta(days=days_ago)
    base = baseline(host, posture, tag)
    await sql(
        "INSERT INTO audit_runs (id, file_hash, original_filename, storage_path, status, detected_vendor, detected_os, created_at, updated_at) "
        "VALUES (:id, :h, :f, :p, 'INGESTED', :v, :o, :t, :t)",
        id=run_id, h=base["device"]["config_sha256"], f=f"{host}-{when:%Y%m%d}.cfg", p=f"raw-configs/{host}-{tag}.cfg", v=spec["vendor"], o=spec["os"], t=when)
    deterministic = {k: copy.deepcopy(base[k]) for k in ("ssh", "telnet", "snmp", "ntp")}
    if host == "edge-sw1":
        deterministic["ssh"]["version"] = "2"  # the independent parser disagrees with the model here, for the trust panel
    kwargs = dict(source_text=config_text(host, posture), parser_agreement=0.97 if host != "edge-sw1" else 0.86, deterministic_baseline=deterministic)
    if not live:  # history: no graph/anomaly side effects, so one device stays one node
        kwargs.update(graph=graph_client.EmptyTopologyGraphProvider(), anomaly=anomaly_client.EmptyAnomalyDetectionProvider())
    await evaluator.evaluate_baseline(base, "CIS", run_id, **kwargs)
    # backdate everything this evaluation wrote
    for table, column in (("audit_evaluations", "evaluated_at"), ("ledger_events", "created_at"), ("compliance_findings", "created_at")):
        await sql(f"UPDATE {table} SET {column} = :t WHERE audit_run_id = :id", t=when, id=run_id)
    await sql("UPDATE audit_runs SET created_at = :t, updated_at = :t WHERE id = :id", t=when, id=run_id)
    return run_id


async def weekend_history(run_id: str, host: str, demo_ids: list[str]):
    """35 days of daily evaluations for one device whose config drifts back on weekends
    (the pattern the frequency analysis should find), and the Monday violation bursts."""
    row = (await db_fetch("SELECT findings_snapshot FROM audit_evaluations WHERE audit_run_id = :id ORDER BY evaluated_at DESC LIMIT 1", id=run_id))[0]
    weekday_snapshot = row[0] if isinstance(row[0], str) else json.dumps(row[0])
    live = json.loads(weekday_snapshot)
    weekend = live + [
        {"control_id": "CIS-NET-1.1.2", "framework": "CIS", "title": "Ensure Telnet is not used for administrative access", "status": "FAIL", "severity": "CRITICAL", "evidence": "telnet.enabled = ENABLED", "remediation": None, "risk_score": 40, "blast_radius": []},
        {"control_id": "CIS-NET-1.2.2", "framework": "CIS", "title": "Ensure default SNMP community strings are not used", "status": "FAIL", "severity": "CRITICAL", "evidence": "Default community string detected: public", "remediation": None, "risk_score": 40, "blast_radius": []},
        {"control_id": "CIS-NET-1.3.1", "framework": "CIS", "title": "Ensure IKE/IPsec Phase 1 proposals do not use DES or 3DES encryption", "status": "FAIL", "severity": "CRITICAL", "evidence": "IKE policy 10 uses 3DES", "remediation": None, "risk_score": 40, "blast_radius": []},
    ]
    # every other device's evaluation sits before the series starts, so only this device moves the fleet score
    # (only the demo's own runs; evaluations of anything else in the database are left exactly as recorded)
    await sql("UPDATE audit_evaluations SET evaluated_at = :t WHERE CAST(audit_run_id AS TEXT) = ANY(:ids) AND CAST(audit_run_id AS TEXT) <> :id",
              t=NOW - timedelta(days=40), ids=[i for i in demo_ids], id=run_id)
    await sql("DELETE FROM audit_evaluations WHERE audit_run_id = :id", id=run_id)
    sha_ = sha("trend", run_id)
    for d in range(35, 0, -1):
        day = NOW - timedelta(days=d)
        snapshot = weekend if day.weekday() >= 5 else live
        await sql("INSERT INTO audit_evaluations (audit_run_id, framework, policy_bundle_version, schema_version, baseline_sha256, findings_snapshot, evaluated_at) "
                  "VALUES (:id, 'CIS', 'cis-generic-level1@1.0.0', '1.0.0', :h, :s, :t)", id=run_id, h=sha_, s=json.dumps(snapshot), t=day.replace(hour=12))
    await sql("INSERT INTO audit_evaluations (audit_run_id, framework, policy_bundle_version, schema_version, baseline_sha256, findings_snapshot, evaluated_at) "
              "VALUES (:id, 'CIS', 'cis-generic-level1@1.0.0', '1.0.0', :h, :s, :t)", id=run_id, h=sha_, s=json.dumps(live), t=NOW - timedelta(minutes=5))
    # The fleet's first audit is not "today": date the initial detections to onboarding, before the series.
    await sql("UPDATE ledger_events SET created_at = :t WHERE event_type = 'VIOLATION_DETECTED' AND CAST(audit_run_id AS TEXT) = ANY(:ids) "
              "AND NOT (payload ? 'seeded')", t=NOW - timedelta(days=44), ids=demo_ids)
    # Monday bursts of new violations (and a quiet midweek trickle)
    for d in range(42, 0, -1):
        day = NOW - timedelta(days=d)
        count = 6 if day.weekday() == 0 else 1 if day.weekday() == 2 else 0
        for _ in range(count):
            await sql("INSERT INTO ledger_events (audit_run_id, control_id, event_type, actor, ruleset_version, payload, created_at) "
                      "VALUES (:id, 'CIS-NET-1.1.2', 'VIOLATION_DETECTED', 'system', '1.1.0', CAST(:p AS JSONB), :t)",
                      id=run_id, p=json.dumps({"seeded": True}), t=day.replace(hour=9))


async def db_fetch(statement: str, **params):
    async with db.async_session() as session:
        return (await session.execute(text(statement), params)).all()


async def main():
    print("Evaluating history for core-rtr1 (drift timeline)…")
    history_ids = [
        await add_run("core-rtr1", "clean", 28, "h28", live=False),
        await add_run("core-rtr1", "clean", 14, "h14", live=False),
        await add_run("core-rtr1", "snmp", 7, "h7", live=False),
    ]
    print("Evaluating the live fleet…")
    ids = {}
    for host, posture in (("core-rtr1", "core_now"), ("dist-sw1", "dist"), ("edge-sw1", "edge_bad"), ("branch-fw", "branch"), ("jun-edge", "jun"), ("pa-fw", "pa_clean")):
        ids[host] = await add_run(host, posture, 0, "live", live=True)
        print(f"  {host}: {ids[host]}")
    print("Building 5 weeks of score history…")
    await weekend_history(ids["branch-fw"], "branch-fw", history_ids + list(ids.values()))

    async with httpx.AsyncClient(timeout=120) as client:
        print("Generating template fixes (edge-sw1, core-rtr1)…")
        for host in ("edge-sw1", "core-rtr1"):
            r = await client.post(f"{REMEDIATION}/remediation/audit-runs/{ids[host]}/generate")
            print(f"  {host}: HTTP {r.status_code}")
        print("Granting a waiver (dist-sw1 Telnet)…")
        r = await client.post(f"{SELF}/waivers", headers={"X-User-Email": "admin@netaudit.local"}, json={
            "audit_run_id": ids["dist-sw1"], "control_id": "CIS-NET-1.1.2", "ticket": "CHG-4417",
            "reason": "Isolated legacy VLAN for mission 4417; compensating control: air-gapped, console-only access",
            "expires_at": (NOW + timedelta(days=30)).isoformat()})
        print("  waiver:", r.status_code, r.json().get("status") if r.status_code == 200 else r.text[:120])
        print("Sealing the ledger…")
        r = await client.post(f"{SELF}/ledger/seal")
        print("  seal:", r.status_code, r.text[:160])
    print("Done.")


asyncio.run(main())
