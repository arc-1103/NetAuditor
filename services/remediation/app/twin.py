"""
Digital-twin reachability check for a proposed change.

Builds a model of the device from its stored baseline (interfaces with
addresses, routing neighbors, and what must stay reachable), applies the ACLs
the proposed script defines and attaches, and evaluates the critical flows the
way the device would (first matching line wins, then the implicit deny). The
question it answers is operational, not syntactic: would this fix drop a BGP/
OSPF session or cut management access from a protected subnet?

Scope, stated plainly:
  * Single-device model, Cisco-style (IOS/EOS) ACL syntax: standard and extended
    named/numbered ACLs, `ip access-group` on interfaces, `access-class` on
    vty lines. A script in another dialect is reported as "not modeled",
    never as safe.
  * It does not model the rest of the network (other devices' policies,
    routing convergence) and it is not Batfish. It catches the common,
    serious mistake: an ACL that denies the control-plane traffic the device
    depends on, or the operator's own way in.
  * Sessions modeled: BGP (tcp/179), OSPF (ip proto 89), EIGRP (proto 88).
    Protected management subnets come from TWIN_PROTECTED_SUBNETS (comma-
    separated CIDRs); SSH (tcp/22) from each must stay permitted.
"""

import ipaddress
import os
import re
from dataclasses import dataclass, field

try:
    from app import formal
except ImportError:  # z3-solver not installed: fall back to evaluating concrete sample packets
    formal = None

PORT_NAMES = {"bgp": 179, "ssh": 22, "telnet": 23, "www": 80, "https": 443, "domain": 53, "ntp": 123, "snmp": 161, "syslog": 514}
IP_PROTOCOLS = {"ospf": 89, "eigrp": 88}
ROUTING_FLOWS = {"bgp": ("tcp", 179), "ospf": ("ospf", None), "eigrp": ("eigrp", None)}
MULTICAST = {"ospf": "224.0.0.5", "eigrp": "224.0.0.10"}


def protected_subnets() -> list[ipaddress.IPv4Network]:
    networks = []
    for item in os.getenv("TWIN_PROTECTED_SUBNETS", "").split(","):
        if item.strip():
            networks.append(ipaddress.ip_network(item.strip(), strict=False))
    return networks


@dataclass
class Entry:
    action: str
    proto: str
    src: ipaddress.IPv4Network
    dst: ipaddress.IPv4Network
    sport: tuple[int, int] | None = None
    dport: tuple[int, int] | None = None
    standard: bool = False


@dataclass
class Binding:
    target: str  # interface name or "vty ..."
    acl: str
    direction: str


@dataclass
class Model:
    acls: dict[str, list[Entry]] = field(default_factory=dict)
    bindings: list[Binding] = field(default_factory=list)


ANY = ipaddress.ip_network("0.0.0.0/0")


def _addr(tokens: list[str], i: int) -> tuple[ipaddress.IPv4Network, int]:
    if tokens[i] == "any":
        return ANY, i + 1
    if tokens[i] == "host":
        return ipaddress.ip_network(f"{tokens[i + 1]}/32"), i + 2
    base = ipaddress.ip_address(tokens[i])
    # optional wildcard mask (next token that looks like an IPv4 address)
    if i + 1 < len(tokens) and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", tokens[i + 1]):
        wildcard = int(ipaddress.ip_address(tokens[i + 1]))
        mask = (~wildcard) & 0xFFFFFFFF
        return ipaddress.ip_network((int(base) & mask, bin(mask).count("1")), strict=False), i + 2
    return ipaddress.ip_network(f"{base}/32"), i + 1


def _port(tokens: list[str], i: int) -> tuple[tuple[int, int] | None, int]:
    if i >= len(tokens) or tokens[i] not in ("eq", "range", "gt", "lt"):
        return None, i

    def number(word: str) -> int:
        return PORT_NAMES.get(word) or int(word)

    op = tokens[i]
    if op == "eq":
        value = number(tokens[i + 1])
        return (value, value), i + 2
    if op == "range":
        return (number(tokens[i + 1]), number(tokens[i + 2])), i + 3
    if op == "gt":
        return (number(tokens[i + 1]) + 1, 65535), i + 2
    return (0, number(tokens[i + 1]) - 1), i + 2


def parse_entry(text: str, *, standard: bool) -> Entry | None:
    tokens = text.lower().split()
    if tokens and tokens[0].isdigit():  # optional sequence number
        tokens = tokens[1:]
    if len(tokens) < 2 or tokens[0] not in ("permit", "deny"):
        return None
    try:
        if standard:
            src, _ = _addr(tokens, 1)
            return Entry(tokens[0], "ip", src, ANY, standard=True)
        proto = tokens[1]
        src, i = _addr(tokens, 2)
        sport, i = _port(tokens, i)
        dst, i = _addr(tokens, i)
        dport, i = _port(tokens, i)
        return Entry(tokens[0], proto, src, dst, sport, dport)
    except (ValueError, IndexError):
        return None


_NAMED = re.compile(r"^\s*ip\s+access-list\s+(standard|extended)\s+(\S+)\s*$", re.IGNORECASE)
_NUMBERED = re.compile(r"^\s*access-list\s+(\d+)\s+((?:permit|deny)\b.*)$", re.IGNORECASE)
_INTERFACE = re.compile(r"^\s*interface\s+(\S+)\s*$", re.IGNORECASE)
_VTY = re.compile(r"^\s*line\s+vty\s+(\S.*)$", re.IGNORECASE)
_GROUP = re.compile(r"^\s*ip\s+access-group\s+(\S+)\s+(in|out)\s*$", re.IGNORECASE)
_CLASS = re.compile(r"^\s*access-class\s+(\S+)\s+in\s*$", re.IGNORECASE)


def parse_script(script: str) -> Model:
    model = Model()
    acl_name: str | None = None
    standard = False
    target: str | None = None
    for line in script.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("!", "#")):
            continue
        if m := _NAMED.match(line):
            acl_name, standard, target = m.group(2), m.group(1).lower() == "standard", None
            model.acls.setdefault(acl_name, [])
            continue
        if m := _NUMBERED.match(line):
            number = int(m.group(1))
            entry = parse_entry(m.group(2), standard=number < 100 or 1300 <= number < 2000)
            if entry:
                model.acls.setdefault(m.group(1), []).append(entry)
            continue
        if m := _INTERFACE.match(line):
            target, acl_name = m.group(1), None
            continue
        if m := _VTY.match(line):
            target, acl_name = f"vty {m.group(1).strip()}", None
            continue
        if stripped.lower() == "exit":
            acl_name = None
            continue
        if acl_name and re.match(r"^\s*(\d+\s+)?(permit|deny)\b", line, re.IGNORECASE):
            entry = parse_entry(stripped, standard=standard)
            if entry:
                model.acls[acl_name].append(entry)
            continue
        if target and (m := _GROUP.match(line)):
            model.bindings.append(Binding(target, m.group(1), m.group(2).lower()))
        elif target and (m := _CLASS.match(line)):
            model.bindings.append(Binding(target, m.group(1), "in"))
    return model


def permits(entries: list[Entry], proto: str, src: str, dst: str, sport: int | None, dport: int | None) -> bool:
    """First match wins; no match = implicit deny (every ACL the script defines is treated as a real ACL)."""
    s, d = ipaddress.ip_address(src), ipaddress.ip_address(dst)
    for entry in entries:
        if entry.proto not in ("ip", proto):
            continue
        if s not in entry.src or (not entry.standard and d not in entry.dst):
            continue
        if entry.sport and (sport is None or not entry.sport[0] <= sport <= entry.sport[1]):
            continue
        if entry.dport and (dport is None or not entry.dport[0] <= dport <= entry.dport[1]):
            continue
        return entry.action == "permit"
    return False


def _interface_for(baseline: dict, neighbor_ip: str) -> dict | None:
    for iface in (baseline.get("topology") or {}).get("interfaces") or []:
        if not (iface.get("ip_address") and iface.get("subnet_mask")):
            continue
        try:
            network = ipaddress.ip_network(f"{iface['ip_address']}/{iface['subnet_mask']}", strict=False)
        except ValueError:
            continue
        if ipaddress.ip_address(neighbor_ip) in network:
            return iface
    return None


def _to_lines(entries: list[Entry]):
    return [formal.Line(e.action, formal.Flow(e.proto, e.src, e.dst, e.sport, e.dport), e.standard) for e in entries]


def _check(entries: list[Entry], flow_spec: dict) -> dict:
    """Does the ACL let `flow_spec` through? Proven for the whole class with Z3 when
    available; otherwise evaluated on one representative packet (and labelled so)."""
    if formal is not None:
        flow = formal.Flow(flow_spec["proto"], flow_spec["src"], flow_spec["dst"], flow_spec.get("sport"), flow_spec.get("dport"))
        result = formal.verify_permitted(_to_lines(entries), flow)
        return {"ok": result["status"] == "PROVEN", "method": "z3-smt", "counterexample": result["counterexample"], "flow": flow}
    src = str(next(flow_spec["src"].hosts(), flow_spec["src"].network_address))
    dst = str(next(flow_spec["dst"].hosts(), flow_spec["dst"].network_address))
    sport = (flow_spec.get("sport") or (50000, 50000))[0]
    dport = (flow_spec.get("dport") or (50000, 50000))[0]
    return {"ok": permits(entries, flow_spec["proto"], src, dst, sport, dport), "method": "sample-packet", "counterexample": None, "flow": None}


def simulate(script: str, baseline: dict | None, protected: list[ipaddress.IPv4Network] | None = None) -> dict:
    model = parse_script(script)
    if not model.acls and not model.bindings:
        return {"modeled": False, "checks": [], "broken": 0, "repairs": [],
                "note": "This change does not add or attach ACLs the twin models (Cisco-style syntax), so no reachability effect was simulated."}
    if not baseline:
        return {"modeled": False, "checks": [], "broken": 0, "repairs": [], "note": "No stored baseline for this audit run, so the device could not be modeled."}
    protected = protected_subnets() if protected is None else protected
    topology = baseline.get("topology") or {}
    interfaces = topology.get("interfaces") or []
    checks: list[dict] = []
    repairs: list[dict] = []
    ephemeral = (1024, 65535)

    for binding in model.bindings:
        entries = model.acls.get(binding.acl)
        if entries is None or binding.direction != "in":
            continue  # an ACL defined elsewhere on the device, or an egress filter: outside this model
        required: list[tuple[str, str, dict]] = []  # (kind, description, flow spec)
        for neighbor in topology.get("routing_neighbors") or []:
            proto = str(neighbor.get("protocol") or "").lower()
            ip = neighbor.get("neighbor_ip")
            iface = _interface_for(baseline, ip) if ip else None
            if proto not in ROUTING_FLOWS or iface is None or iface["name"] != binding.target:
                continue
            peer, local = ipaddress.ip_network(f"{ip}/32"), ipaddress.ip_network(f"{iface['ip_address']}/32")
            label = f"{proto.upper()} session with {ip} on {binding.target} (ACL {binding.acl} in)"
            if proto == "bgp":
                required.append(("routing", label, {"proto": "tcp", "src": peer, "dst": local, "sport": ephemeral, "dport": (179, 179)}))
                required.append(("routing", label, {"proto": "tcp", "src": peer, "dst": local, "sport": (179, 179), "dport": ephemeral}))
            else:
                required.append(("routing", label, {"proto": ROUTING_FLOWS[proto][0], "src": peer, "dst": ipaddress.ip_network(f"{MULTICAST[proto]}/32")}))
        local_ip = next((i["ip_address"] for i in interfaces if i.get("ip_address")), None)
        if local_ip:
            for network in protected:
                required.append(("management", f"SSH from protected subnet {network} via {binding.target} (ACL {binding.acl} in)",
                                 {"proto": "tcp", "src": network, "dst": ipaddress.ip_network(f"{local_ip}/32"), "sport": ephemeral, "dport": (22, 22)}))

        # one check per described path: it holds only if every packet class behind it is permitted
        by_label: dict[str, list[dict]] = {}
        for kind, label, spec in required:
            outcome = _check(entries, spec)
            by_label.setdefault((kind, label), []).append(outcome)
        binding_broken = False
        for (kind, label), outcomes in by_label.items():
            failing = next((o for o in outcomes if not o["ok"]), None)
            binding_broken = binding_broken or failing is not None
            checks.append({
                "kind": kind, "description": label, "result": "BROKEN" if failing else "PRESERVED",
                "method": outcomes[0]["method"],
                "counterexample": failing["counterexample"] if failing else None,
            })

        if binding_broken and formal is not None:
            must_permit = [o["flow"] for outcomes in by_label.values() for o in outcomes]
            local = ipaddress.ip_network(f"{local_ip}/32") if local_ip else formal.ipaddress.ip_network("0.0.0.0/0")
            must_block = [formal.Flow("tcp", formal.ipaddress.ip_network("0.0.0.0/0"), local, None, (23, 23))]
            fixed = formal.cegis_repair(_to_lines(entries), must_permit, must_block)
            repairs.append({"acl": binding.acl, "target": binding.target, "status": fixed["status"],
                            "add_lines": fixed["added"], "rounds": fixed["rounds"], "reason": fixed.get("reason")})

    broken = [c for c in checks if c["result"] == "BROKEN"]
    note = None if checks else "ACLs were parsed, but none is attached inbound to an interface carrying a modeled routing session or protecting a configured management subnet."
    return {"modeled": True, "checks": checks, "broken": len(broken), "repairs": repairs, "note": note,
            "method": "z3-smt" if formal is not None else "sample-packet"}


def risk_flags(result: dict) -> list[str]:
    return [f"Digital twin: would break — {c['description']}" for c in result["checks"] if c["result"] == "BROKEN"]
