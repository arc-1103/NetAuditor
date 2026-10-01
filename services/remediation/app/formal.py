"""
Formal verification of access lists with an SMT solver (Z3), plus
counterexample-guided repair (CEGIS).

An ACL is encoded as a bit-vector formula over one symbolic packet
(src/dst 32-bit, protocol 8-bit, source/destination port 16-bit) with the
device's semantics: the first matching line decides, and no match is the
implicit deny. A *requirement* is a whole class of packets that must be
permitted (for example "TCP to port 22 from every host in 192.168.50.0/24").
Asking the solver whether any packet in the class is denied either proves the
ACL lets the entire class through (UNSAT) or returns a concrete counterexample
packet (SAT) — a proof over every address and port in the class, not a test
of a few samples.

CEGIS (verify -> counterexample -> strengthen -> verify) repairs an ACL that
fails: take the counterexample, add a permit line covering its requirement
class just before the line that blocked it, re-verify, and repeat. A candidate
line is rejected if it would admit a class that must stay blocked, in which
case the result is UNREPAIRABLE rather than an unsafe "fix".

Scope: a single ACL's packet-filtering behaviour. The solver proves facts about
the model it is given — the parsed ACL and the stated requirements — not about
the rest of the network.
"""

import ipaddress
from dataclasses import dataclass

import z3

PROTOCOL_NUMBERS = {"tcp": 6, "udp": 17, "icmp": 1, "ospf": 89, "eigrp": 88}
EPHEMERAL = (1024, 65535)


@dataclass(frozen=True)
class Flow:
    """A set of packets: protocol ('ip' = any), prefixes, optional port ranges."""
    proto: str
    src: ipaddress.IPv4Network
    dst: ipaddress.IPv4Network
    sport: tuple[int, int] | None = None
    dport: tuple[int, int] | None = None


@dataclass(frozen=True)
class Line:
    action: str  # "permit" | "deny"
    flow: Flow
    standard: bool = False  # standard ACLs match the source address only


class Packet:
    def __init__(self, tag: str = ""):
        self.src = z3.BitVec(f"src{tag}", 32)
        self.dst = z3.BitVec(f"dst{tag}", 32)
        self.proto = z3.BitVec(f"proto{tag}", 8)
        self.sport = z3.BitVec(f"sport{tag}", 16)
        self.dport = z3.BitVec(f"dport{tag}", 16)


def _in_prefix(var: z3.BitVecRef, network: ipaddress.IPv4Network):
    lo, hi = int(network.network_address), int(network.broadcast_address)
    return z3.And(z3.UGE(var, z3.BitVecVal(lo, 32)), z3.ULE(var, z3.BitVecVal(hi, 32)))


def _in_ports(var: z3.BitVecRef, ports: tuple[int, int] | None):
    if ports is None:
        return z3.BoolVal(True)
    return z3.And(z3.UGE(var, z3.BitVecVal(ports[0], 16)), z3.ULE(var, z3.BitVecVal(ports[1], 16)))


def in_flow(pkt: Packet, flow: Flow, *, source_only: bool = False):
    conditions = [_in_prefix(pkt.src, flow.src)]
    if not source_only:
        conditions.append(_in_prefix(pkt.dst, flow.dst))
        if flow.proto != "ip":
            conditions.append(pkt.proto == z3.BitVecVal(PROTOCOL_NUMBERS[flow.proto], 8))
        conditions += [_in_ports(pkt.sport, flow.sport), _in_ports(pkt.dport, flow.dport)]
    return z3.And(*conditions)


def permitted(pkt: Packet, lines: list[Line]):
    """First match wins; no match is the implicit deny."""
    verdict = z3.BoolVal(False)
    for line in reversed(lines):
        verdict = z3.If(in_flow(pkt, line.flow, source_only=line.standard), z3.BoolVal(line.action == "permit"), verdict)
    return verdict


def _describe(model: z3.ModelRef, pkt: Packet) -> dict:
    def value(var, default=0):
        evaluated = model.eval(var, model_completion=True)
        return evaluated.as_long() if z3.is_bv_value(evaluated) else default

    proto = value(pkt.proto)
    names = {number: name for name, number in PROTOCOL_NUMBERS.items()}
    return {
        "src": str(ipaddress.ip_address(value(pkt.src))), "dst": str(ipaddress.ip_address(value(pkt.dst))),
        "proto": names.get(proto, str(proto)), "sport": value(pkt.sport), "dport": value(pkt.dport),
    }


def verify_permitted(lines: list[Line], flow: Flow) -> dict:
    """PROVEN if every packet in `flow` is permitted; else a counterexample packet."""
    pkt, solver = Packet(), z3.Solver()
    solver.add(in_flow(pkt, flow), z3.Not(permitted(pkt, lines)))
    if solver.check() == z3.unsat:
        return {"status": "PROVEN", "counterexample": None}
    return {"status": "COUNTEREXAMPLE", "counterexample": _describe(solver.model(), pkt)}


def overlaps(a: Flow, b: Flow) -> bool:
    pkt, solver = Packet(), z3.Solver()
    solver.add(in_flow(pkt, a), in_flow(pkt, b))
    return solver.check() == z3.sat


def to_ios(line: Line) -> str:
    def address(network: ipaddress.IPv4Network) -> str:
        if network.prefixlen == 0:
            return "any"
        if network.prefixlen == 32:
            return f"host {network.network_address}"
        return f"{network.network_address} {network.hostmask}"

    def ports(port_range: tuple[int, int] | None) -> str:
        if port_range is None:
            return ""
        return f" eq {port_range[0]}" if port_range[0] == port_range[1] else f" range {port_range[0]} {port_range[1]}"

    flow = line.flow
    if line.standard:
        return f"{line.action} {address(flow.src)}"
    return f"{line.action} {flow.proto} {address(flow.src)}{ports(flow.sport)} {address(flow.dst)}{ports(flow.dport)}"


def cegis_repair(lines: list[Line], must_permit: list[Flow], must_block: list[Flow], *, max_rounds: int = 12) -> dict:
    """Add the fewest permit lines needed so every `must_permit` class is proven,
    never admitting a `must_block` class. Returns the repaired lines and a trace."""
    current, added, trace = list(lines), [], []
    for round_number in range(1, max_rounds + 1):
        failing = next(((flow, result) for flow in must_permit
                        if (result := verify_permitted(current, flow))["status"] == "COUNTEREXAMPLE"), None)
        if failing is None:
            status = "ALREADY_SAFE" if not added else "REPAIRED"
            return {"status": status, "lines": current, "added": [to_ios(a) for a in added], "rounds": round_number - 1, "trace": trace}
        flow, result = failing
        for blocked in must_block:
            if overlaps(flow, blocked):
                return {"status": "UNREPAIRABLE", "lines": lines, "added": [], "rounds": round_number,
                        "trace": trace, "reason": f"permitting {flow.proto} {flow.src} -> {flow.dst} would also admit traffic that must stay blocked"}
        candidate = Line("permit", flow, standard=False)
        blocker = _first_matching(current, result["counterexample"])
        position = blocker if blocker is not None else len(current)
        current.insert(position, candidate)
        added.append(candidate)
        trace.append({"round": round_number, "counterexample": result["counterexample"], "inserted_at": position + 1, "line": to_ios(candidate)})
    return {"status": "UNREPAIRABLE", "lines": lines, "added": [], "rounds": max_rounds, "trace": trace, "reason": "no repair found within the round limit"}


def _first_matching(lines: list[Line], packet: dict) -> int | None:
    src, dst = ipaddress.ip_address(packet["src"]), ipaddress.ip_address(packet["dst"])
    for index, line in enumerate(lines):
        flow = line.flow
        if src not in flow.src:
            continue
        if not line.standard:
            if dst not in flow.dst or flow.proto not in ("ip", packet["proto"]):
                continue
            if flow.sport and not flow.sport[0] <= packet["sport"] <= flow.sport[1]:
                continue
            if flow.dport and not flow.dport[0] <= packet["dport"] <= flow.dport[1]:
                continue
        return index
    return None
