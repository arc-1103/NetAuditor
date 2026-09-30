"""
Builds the "proposed" baseline for app/counterfactual.py from a single control.

counterfactual.py deliberately does not derive a proposed baseline from a
remediation script's CLI text (see its docstring) — the caller supplies both
sides. This module is that caller for the UI's "simulate this fix": for each
control it sets the normalized SecurityBaseline fields to the state the
control's Rego rule passes on. It works on the normalized schema, so it is
vendor-independent, and it assumes the fix achieves the intended state — a
simulation, not proof the vendor CLI does so.
"""

from copy import deepcopy

_DEFAULT_COMMUNITIES = {"public", "private"}
_WEAK_IKE = {"DES", "3DES"}


def _set(baseline: dict, path: tuple[str, ...], value) -> None:
    node = baseline
    for key in path[:-1]:
        node = node.setdefault(key, {})
    node[path[-1]] = value


def _drop_default_communities(baseline: dict) -> None:
    snmp = baseline.setdefault("snmp", {})
    snmp["community_strings"] = [c for c in snmp.get("community_strings") or [] if str(c).lower() not in _DEFAULT_COMMUNITIES]


def _strengthen_ike(baseline: dict) -> None:
    crypto = baseline.setdefault("crypto", {})
    crypto["ike_policies"] = [
        {**p, "encryption": "AES256"} if p.get("encryption") in _WEAK_IKE else p
        for p in crypto.get("ike_policies") or []
    ]


_FIXES = {
    "CIS-NET-1.1.1": lambda b: _set(b, ("ssh", "version"), "2"),
    "CIS-NET-1.1.2": lambda b: _set(b, ("telnet", "enabled"), "DISABLED"),
    "CIS-NET-1.1.3": lambda b: _set(b, ("ssh", "management_acl"), "MGMT-ONLY"),
    "CIS-NET-1.2.1": lambda b: _set(b, ("snmp", "version"), "v3"),
    "CIS-NET-1.2.2": _drop_default_communities,
    "CIS-NET-1.3.1": _strengthen_ike,
    "CIS-NET-1.4.1": lambda b: _set(b, ("ntp", "authentication_enabled"), True),
    "CIS-NET-1.5.1": lambda b: _set(b, ("aaa", "password_encryption"), "ENABLED"),
    "CIS-NET-1.6.1": lambda b: _set(b, ("banners", "login_banner_present"), True),
    "CIS-NET-1.7.1": lambda b: _set(b, ("services", "http_server_enabled"), "DISABLED"),
    "CIS-NET-1.8.1": lambda b: (_set(b, ("logging", "syslog_enabled"), True), _set(b, ("logging", "syslog_hosts"), ["remote-syslog"])),
}


def apply_fix(baseline: dict, control_id: str) -> dict | None:
    """A copy of `baseline` with `control_id` fixed, or None when this control
    has no simulation rule."""
    fix = _FIXES.get(control_id)
    if fix is None:
        return None
    proposed = deepcopy(baseline)
    fix(proposed)
    return proposed
