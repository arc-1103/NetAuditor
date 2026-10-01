# Digital twin reachability analysis

A fix is approved only if it is operationally safe, not just syntactically valid.
`services/remediation/app/twin.py` builds a model of the device from the baseline
stored with its audit run and applies the proposed script to it.

## What it simulates

- The ACLs the script defines (standard and extended, named and numbered) and where
  it attaches them (`ip access-group` on an interface, `access-class` on a vty line),
  evaluated as the device does: first matching line wins, then the implicit deny.
- **Routing sessions** on the interface an inbound ACL protects: BGP (both directions
  of tcp/179), OSPF and EIGRP (their IP protocols).
- **Management access**: SSH from every subnet listed in `TWIN_PROTECTED_SUBNETS`.

Each check is reported PRESERVED or BROKEN. Any BROKEN turns the proposal into
RISK_FLAGS (it cannot be approved) and names the session or subnet it would cut.

## Example

The shipped management-ACL fix permits `10.0.0.0/24` by default. If operators work
from `192.168.50.0/24` and that is listed as protected, the twin reports
`BROKEN — SSH from protected subnet 192.168.50.0/24 via vty 0 15`. Setting
`management_network=192.168.50.0` for the fix clears it.

## Formal verification (Z3) and CEGIS

The ACL checks are proofs, not tests. `services/remediation/app/formal.py` encodes
the ACL as a bit-vector formula over one symbolic packet (32-bit source and
destination, 8-bit protocol, 16-bit ports) with the device's semantics — first
match wins, then the implicit deny. A requirement is a whole *class* of packets
(for example "TCP/22 from every host in 192.168.50.0/24"); Z3 either proves the
entire class is permitted or returns a concrete packet that is not. Sampling one
host would miss an ACL that permits only half of a subnet; the solver does not.

When a check fails, counterexample-guided repair (CEGIS) runs: take the
blocked packet, add a permit line for its requirement class just before the line
that blocked it, re-verify, repeat. A candidate that would also admit a class
that must stay blocked (Telnet to the device) is rejected, and the result is
reported UNREPAIRABLE rather than an unsafe suggestion. The suggested lines
appear in the UI and the PDF; nothing is applied automatically.

AI-drafted fixes (from the language model) go through the same check, so the
model proposes and the solver decides. Without `z3-solver` installed the twin
falls back to evaluating one sample packet and labels every result
"sample check".

## Limits

- Single device, Cisco-style ACL syntax. Junos, PAN-OS and FortiOS scripts are
  reported as "not modeled" — never as safe.
- BGP is checked conservatively in both directions; an ACL permitting only the
  neighbor-initiated direction is flagged because either side may initiate.
- The proofs are about the model: the parsed ACL and the stated requirements. They say nothing about
  other devices, route convergence or NAT. It is not Batfish;
  the Batfish integration remains a mock until snapshots are wired in.
