"""
Confidence-weighted auto-decision engine — docs/Additional-Features.md §2.

Classifies a remediation proposal against policy/decision_table.yaml and
returns which action tier it falls into (BLOCK / DUAL_APPROVAL /
SINGLE_APPROVAL / AUTO_APPLY).

This module only classifies. It never bypasses the human-approval gate in
app/db.approve() — this codebase has no live device-apply path anywhere
today (approval only ever flips a database column; an operator runs the
script by hand), so there is nothing an AUTO_APPLY verdict could safely
bypass yet. Treat `action == "AUTO_APPLY"` as "eligible for auto-apply once
a real apply path exists and is wired to trust this table", not as
"already applied" — see README/PR notes.
"""

import functools
from pathlib import Path

import yaml

DECISION_TABLE_PATH = Path(__file__).parents[1] / "policy" / "decision_table.yaml"

# No separate "remediation risk" signal exists anywhere in this codebase;
# the finding's own CIS severity is the only grounded input available.
SEVERITY_TO_RISK = {"CRITICAL": "HIGH", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}

# An unknown blast radius (the caller never passed one) must never score as
# favorably as a confirmed-zero one — it has to land past
# block-large-blast-radius in decision_table.yaml, not silently qualify for
# SINGLE_APPROVAL or AUTO_APPLY's small-blast-radius rows.
UNKNOWN_BLAST_RADIUS = 999


def blast_radius_count(blast_radius: list[str] | None) -> int:
    return UNKNOWN_BLAST_RADIUS if blast_radius is None else len(blast_radius)


@functools.lru_cache(maxsize=1)
def _load_table() -> dict:
    return yaml.safe_load(DECISION_TABLE_PATH.read_text(encoding="utf-8"))


def risk_for_severity(severity: str) -> str:
    return SEVERITY_TO_RISK.get(str(severity).upper(), "HIGH")


def _matches(when: dict, parser_agreement: float, blast_radius: int, risk: str) -> bool:
    if "parser_agreement_min" in when and parser_agreement < when["parser_agreement_min"]:
        return False
    if "parser_agreement_max" in when and parser_agreement >= when["parser_agreement_max"]:
        return False
    if "blast_radius_min" in when and blast_radius < when["blast_radius_min"]:
        return False
    if "blast_radius_max" in when and blast_radius > when["blast_radius_max"]:
        return False
    if "risk" in when and risk not in when["risk"]:
        return False
    return True


def decide(*, parser_agreement: float | None, blast_radius: int, severity: str) -> dict:
    """Returns {"action", "rule_id", "ruleset_version", "reason", "risk",
    "blast_radius_count"}. The last two are echoed back (not just consumed
    internally) because app/approval_matrix.py's RBAC check
    (docs/Additional-Features.md §7) needs the same risk/blast-radius
    inputs this table used, and must see the exact values that produced
    this action rather than re-deriving its own.

    parser_agreement is 0..1; None (e.g. a dry-run /evaluate call with no
    audit_run_id, so no parsing_confidence was ever recorded) is treated as
    the least trustworthy value — it must never look more confident than an
    actually-low score would.
    """
    table = _load_table()
    agreement = parser_agreement if parser_agreement is not None else 0.0
    risk = risk_for_severity(severity)
    for rule in table["rules"]:
        if _matches(rule.get("when", {}), agreement, blast_radius, risk):
            return {
                "action": rule["action"],
                "rule_id": rule["id"],
                "ruleset_version": table["version"],
                "reason": rule.get("reason", ""),
                "risk": risk,
                "blast_radius_count": blast_radius,
            }
    # The table always ends in an unconditional catch-all rule (`when: {}`),
    # so this is unreachable — but a decision engine must never return
    # nothing for a proposal it was asked to classify.
    return {
        "action": "SINGLE_APPROVAL", "rule_id": "fallback", "ruleset_version": table["version"],
        "reason": "", "risk": risk, "blast_radius_count": blast_radius,
    }
