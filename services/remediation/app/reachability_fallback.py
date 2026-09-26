"""
Demo-Safe Reachability Fallback — docs/Additional-Features.md §4.

A lighter-weight, dependency-free reachability estimator that parses only
the ACL/access-class/route statements a proposed remediation script itself
adds or removes, and flags the direction (narrows or widens permitted
traffic) wherever that direction is knowable without modeling the whole
network topology the way Batfish would. Recommended there over attempting
real Batfish first: "zero external dependency risk... kept permanently as
a fast first-pass filter, with Batfish invoked only for changes it flags
as non-trivial."

This reads only the script text passed to app/batfish_client.py's
preflight() — not the device's current live configuration, since no
baseline-threading exists yet between Compliance and this service for
that. A change is classified narrowing/widening only when the classification
holds regardless of what the rest of the device's config looks like
(monotonic once the change itself is known):
  - Applying an access-class/trusthost restriction to a line that had none
    visible in this script can only narrow what reaches it — "no filter"
    is always a superset of "any filter" — and removing one can only widen.
  - Removing a `permit`/`deny` entry from an existing ACL can only narrow
    (permit removed) or widen (deny removed) — the entry demonstrably
    existed and mattered before this script ran.
  - *Adding* a new `permit`/`deny` entry is deliberately NOT classified:
    the same script may be defining a brand-new ACL that has no effect
    until it's separately applied (see ios_ssh_mgmt_acl_fix.j2, which
    creates NETAUDIT-MGMT and applies it via access-class in the same
    script) — attributing a direction to the entry itself would double-count
    or mislabel that case. The access-class/trusthost line the ACL gets
    attached to is what actually carries the narrowing signal.
  - `transport input <x>`/`set allowaccess <x>` REPLACE the whole allowed
    set rather than add/remove from it, so without the prior value the
    direction can't be determined at all — except `transport input none`,
    which is unambiguous (services/parsing's own extractor treats it the
    same way: no signal is never allowed to look like a known answer).

"No signal" (an empty estimate) for a script in neither dialect, or with no
ACL/route lines at all, is deliberate — never a guessed default, the same
discipline services/parsing/app/deterministic_extractor.py's own module
docstring documents for exactly this kind of best-effort parser. Vendor
coverage matches what services/remediation/templates/*.j2 actually ships
today: Cisco/Arista-style IOS ACL syntax and the FortiOS admin-access
directives those templates use (`set allowaccess`, `set trusthostN`) — not
`config firewall policy`, which no shipped template touches.

Deliberately narrower than Batfish, by design: no multi-hop topology, no
BGP/OSPF impact modeling — a routing statement is recorded for blast-radius
visibility only, never classified as narrowing/widening.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class ReachabilityEstimate:
    newly_blocked: list[str] = field(default_factory=list)
    newly_permitted: list[str] = field(default_factory=list)
    routing_statements_touched: list[str] = field(default_factory=list)
    touched_interfaces: list[str] = field(default_factory=list)
    touched_acl_names: list[str] = field(default_factory=list)

    @property
    def blast_radius(self) -> list[str]:
        return sorted(set(self.touched_interfaces) | set(self.touched_acl_names))

    def to_dict(self) -> dict:
        return {
            "newly_blocked": self.newly_blocked,
            "newly_permitted": self.newly_permitted,
            "routing_statements_touched": self.routing_statements_touched,
            "blast_radius": self.blast_radius,
        }


_INTERFACE_LINE = re.compile(r"^\s*interface\s+(\S+)\s*$", re.IGNORECASE)
_VTY_LINE = re.compile(r"^\s*line\s+vty\s+(\S.*)$", re.IGNORECASE)
_TRANSPORT_INPUT = re.compile(r"^\s*transport\s+input\s+(\S.*)$", re.IGNORECASE)
_ACCESS_CLASS = re.compile(r"^\s*(no\s+)?access-class\s+(\S+)\s+in\b", re.IGNORECASE)
_NAMED_ACL_START = re.compile(r"^\s*ip\s+access-list\s+(?:standard|extended)\s+(\S+)", re.IGNORECASE)
_ACL_ENTRY = re.compile(r"^\s*(no\s+)?(permit|deny)\b(.*)$", re.IGNORECASE)
_NUMBERED_ACL = re.compile(r"^\s*(no\s+)?access-list\s+(\d+)\s+(permit|deny)\b(.*)$", re.IGNORECASE)
_ROUTE_STATEMENT = re.compile(r"^\s*(no\s+)?(ip\s+route\b|router\s+(?:bgp|ospf)\b|neighbor\s+\S+)", re.IGNORECASE)
_FORTINET_ALLOWACCESS = re.compile(r"^\s*set\s+allowaccess\s+(\S.*)$", re.IGNORECASE)
_FORTINET_TRUSTHOST = re.compile(r"^\s*set\s+trusthost\d+\s+(\S.*)$", re.IGNORECASE)


def _acl_entry_direction(removed: bool, action: str) -> str | None:
    """Only a *removal* has a knowable direction — see module docstring."""
    if not removed:
        return None
    return "newly_permitted" if action == "deny" else "newly_blocked"


def estimate_reachability_impact(script: str) -> ReachabilityEstimate:
    estimate = ReachabilityEstimate()
    current_vty: str | None = None
    current_acl_name: str | None = None

    for raw_line in script.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped:
            continue

        if m := _INTERFACE_LINE.match(line):
            estimate.touched_interfaces.append(m.group(1))
            current_vty = None
            current_acl_name = None
            continue

        if m := _VTY_LINE.match(line):
            current_vty = f"vty {m.group(1).strip()}"
            estimate.touched_interfaces.append(current_vty)
            current_acl_name = None
            continue

        if m := _TRANSPORT_INPUT.match(line):
            protocols = m.group(1).strip().lower()
            if protocols == "none":
                context = current_vty or "an interface"
                estimate.newly_blocked.append(f"{context}: all remote transport disabled ('transport input none')")
            continue

        if m := _ACCESS_CLASS.match(line):
            removed, acl_name = bool(m.group(1)), m.group(2)
            context = current_vty or "an interface"
            estimate.touched_acl_names.append(acl_name)
            if removed:
                estimate.newly_permitted.append(f"{context}: access-class {acl_name} removed — no longer ACL-restricted")
            else:
                estimate.newly_blocked.append(f"{context}: access-class {acl_name} applied — now ACL-restricted")
            continue

        if m := _NAMED_ACL_START.match(line):
            current_acl_name = m.group(1)
            estimate.touched_acl_names.append(current_acl_name)
            continue

        if current_acl_name and (m := _ACL_ENTRY.match(line)):
            removed, action, rest = bool(m.group(1)), m.group(2).lower(), m.group(3).strip()
            direction = _acl_entry_direction(removed, action)
            if direction:
                getattr(estimate, direction).append(f"ACL {current_acl_name}: removes '{action} {rest}'")
            continue
        if current_acl_name and not line.startswith((" ", "\t")):
            current_acl_name = None  # left the ACL's indented sub-config block

        if m := _NUMBERED_ACL.match(line):
            removed, acl_num, action, rest = bool(m.group(1)), m.group(2), m.group(3).lower(), m.group(4).strip()
            estimate.touched_acl_names.append(acl_num)
            direction = _acl_entry_direction(removed, action)
            if direction:
                getattr(estimate, direction).append(f"access-list {acl_num}: removes '{action} {rest}'")
            continue

        if m := _FORTINET_TRUSTHOST.match(line):
            estimate.newly_blocked.append(f"admin access restricted to trusted host {m.group(1).strip()}")
            continue

        if _FORTINET_ALLOWACCESS.match(line):
            continue  # replaces the whole allowed set — direction unknowable without the prior value

        if m := _ROUTE_STATEMENT.match(line):
            estimate.routing_statements_touched.append(stripped)
            continue

    return estimate
